package api

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mitchellh/cli"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	commoncli "github.com/spiffe/spire/pkg/common/cli"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/clitest"
	"github.com/spiffe/spire/test/fakes/fakeworkloadapi"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// flakyWorkloadAPI serves the raw Workload API and fails the first
// failFirstX509Streams FetchX509SVID streams (optionally after delivering an
// update) so client reconnect behavior can be exercised.
type flakyWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	x509Resp *workload.X509SVIDResponse

	failFirstX509Streams int32
	deliverBeforeFail    bool
	x509Streams          atomic.Int32
	activeX509Streams    atomic.Int32
}

func (s *flakyWorkloadAPI) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := requireSecurityHeader(stream.Context()); err != nil {
		return err
	}

	streamNum := s.x509Streams.Add(1)
	s.activeX509Streams.Add(1)
	defer s.activeX509Streams.Add(-1)

	if streamNum <= s.failFirstX509Streams {
		if s.deliverBeforeFail {
			if err := stream.Send(s.x509Resp); err != nil {
				return err
			}
		}
		return status.Error(codes.Unavailable, "simulated stream failure")
	}

	if err := stream.Send(s.x509Resp); err != nil {
		return err
	}
	// Healthy stream: hold the subscription open until the client goes away.
	<-stream.Context().Done()
	return nil
}

func requireSecurityHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md["workload.spiffe.io"]) != 1 || md["workload.spiffe.io"][0] != "true" {
		return status.Error(codes.InvalidArgument, "request received without security header")
	}
	return nil
}

// countingX509Watcher wraps the CLI watcher so tests can count the updates
// delivered across reconnects while still exercising the CLI print callback.
type countingX509Watcher struct {
	inner   *watcher
	updates atomic.Int32
}

func (w *countingX509Watcher) OnX509ContextUpdate(x509Context *workloadapi.X509Context) {
	w.updates.Add(1)
	w.inner.OnX509ContextUpdate(x509Context)
}

func (w *countingX509Watcher) OnX509ContextWatchError(err error) {
	w.inner.OnX509ContextWatchError(err)
}

// runCommand executes a CLI command against addr using a workload client
// maker that captures the client so the test can assert its connection was
// released after the command exits.
func runCommand(t *testing.T, addr net.Addr, newCmd func(*commoncli.Env, workloadClientMaker) cli.Command, extraArgs ...string) (int, *workloadClient, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()

	stdin := new(bytes.Buffer)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)

	var made *workloadClient
	maker := func(_ context.Context, clientAddr net.Addr, timeout time.Duration) (*workloadClient, error) {
		c, err := newWorkloadClient(context.Background(), clientAddr, timeout)
		if err != nil {
			return nil, err
		}
		made = c
		return c, nil
	}

	cmd := newCmd(&commoncli.Env{
		Stdin:  stdin,
		Stdout: stdout,
		Stderr: stderr,
	}, maker)

	args := append([]string{clitest.AddrArg, clitest.GetAddr(addr)}, extraArgs...)
	rc := cmd.Run(args)
	return rc, made, stdout, stderr
}

func requireConnectionReleased(t *testing.T, c *workloadClient) {
	t.Helper()
	require.NotNil(t, c, "workload client was never created")
	require.Equal(t, connectivity.Shutdown, c.conn.GetState(),
		"client connection was not released after the command exited")
}

func x509WatchResponse(t *testing.T) *workload.X509SVIDResponse {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := testca.New(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromString("spiffe://example.org/foo"))
	return &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{
			{
				SpiffeId:    svid.ID.String(),
				X509Svid:    x509util.DERFromCertificates(svid.Certificates),
				X509SvidKey: pkcs8FromSigner(t, svid.PrivateKey),
				Bundle:      x509util.DERFromCertificates(ca.Bundle().X509Authorities()),
			},
		},
		Crl:              [][]byte{},
		FederatedBundles: map[string][]byte{},
	}
}

// TestFetchX509ReconnectsAfterStreamFailureAndReleasesConnection ensures the
// one-shot fetch client releases its connection even when the watch stream
// fails, and that a subsequent invocation reconnects and succeeds without
// leaking server-side streams.
func TestFetchX509ReconnectsAfterStreamFailureAndReleasesConnection(t *testing.T) {
	resp := x509WatchResponse(t)
	server := &flakyWorkloadAPI{
		x509Resp:             resp,
		failFirstX509Streams: 1,
	}
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})

	// First invocation hits the failing stream; the connection must still be
	// released when the command exits with an error.
	rc, firstClient, _, stderr := runCommand(t, addr, newFetchX509Command, "-output", "pretty")
	require.Equal(t, 1, rc)
	require.Contains(t, stderr.String(), "simulated stream failure")
	requireConnectionReleased(t, firstClient)
	require.Equal(t, int32(1), server.x509Streams.Load())

	// The agent stream for the failed call must not linger.
	require.Eventually(t, func() bool { return server.activeX509Streams.Load() == 0 },
		5*time.Second, 10*time.Millisecond, "failed stream subscription was not released")

	// Reconnect: a fresh invocation establishes a new stream and succeeds.
	rc, secondClient, stdout, _ := runCommand(t, addr, newFetchX509Command, "-output", "pretty")
	require.Equal(t, 0, rc)
	require.Contains(t, stdout.String(), "SPIFFE ID:")
	requireConnectionReleased(t, secondClient)
	require.Equal(t, int32(2), server.x509Streams.Load(), "expected exactly one reconnect stream")

	require.Eventually(t, func() bool { return server.activeX509Streams.Load() == 0 },
		5*time.Second, 10*time.Millisecond, "reconnected stream subscription was not released")
}

// TestFetchJWTReleasesConnectionOnStreamError ensures a JWT bundle stream
// failure still releases the underlying connection.
func TestFetchJWTReleasesConnectionOnStreamError(t *testing.T) {
	workloadAPI := fakeworkloadapi.New(t, &fakeworkloadapi.FakeRequest{
		Req:  &workload.JWTBundlesRequest{},
		Resp: &workload.JWTBundlesResponse{},
		Err:  errors.New("error fetching bundles"),
	})

	rc, client, _, stderr := runCommand(t, workloadAPI.Addr(), newFetchJWTCommandWithEnv, "-audience", "foo")
	require.Equal(t, 1, rc)
	require.Contains(t, stderr.String(), "error fetching bundles")
	requireConnectionReleased(t, client)
}

// TestWatchX509ReconnectsAfterDisconnectAndReleasesOnCancel exercises the same
// Workload API watch call used by "spire-agent api watch": the first stream
// delivers an update and then drops, the client reconnects and receives the
// update again, and cancelling the watch context terminates cleanly and
// releases the server-side subscription.
func TestWatchX509ReconnectsAfterDisconnectAndReleasesOnCancel(t *testing.T) {
	resp := x509WatchResponse(t)
	server := &flakyWorkloadAPI{
		x509Resp:             resp,
		failFirstX509Streams: 1,
		deliverBeforeFail:    true,
	}
	addr := spiretest.StartGRPCServer(t, func(s *grpc.Server) {
		workload.RegisterSpiffeWorkloadAPIServer(s, server)
	})

	clientOption, err := util.GetWorkloadAPIClientOption(addr)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher := &countingX509Watcher{inner: newWatcher()}
	errCh := make(chan error, 1)
	go func() {
		errCh <- workloadapi.WatchX509Context(ctx, watcher, clientOption)
	}()

	// The first stream delivered an update before dropping; the reconnected
	// stream must deliver the current state again.
	require.Eventually(t, func() bool { return watcher.updates.Load() == 2 },
		20*time.Second, 50*time.Millisecond,
		"watcher did not receive an update after reconnecting")
	require.Equal(t, int32(2), server.x509Streams.Load(),
		"expected exactly one reconnect, no retry storm")

	// Disconnect the watch client: the watch call must terminate cleanly and
	// the server-side stream (subscription) must be released.
	cancel()
	select {
	case err := <-errCh:
		require.Equal(t, codes.Canceled, status.Code(err), "expected a clean cancellation error")
	case <-time.After(10 * time.Second):
		t.Fatal("WatchX509Context did not return after the context was canceled")
	}

	require.Eventually(t, func() bool { return server.activeX509Streams.Load() == 0 },
		5*time.Second, 10*time.Millisecond,
		"watch subscription was not released after cancellation")
}
