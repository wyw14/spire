package workload_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	workloadPB "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/agent/endpoints/workload"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/api/middleware"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// statsFakeManager is a workload.Manager fake serving a mutable current
// update so reconnected watch streams can be asserted to receive the fresh
// state (and no stale bundle).
type statsFakeManager struct {
	stats *cache.Stats

	mu        sync.RWMutex
	x509      *cache.X509WorkloadUpdate
	wit       *cache.WITWorkloadUpdate
	entries   []*common.RegistrationEntry
	jwtTokens map[string]string

	subscribers atomic.Int32
}

func (m *statsFakeManager) setX509Update(update *cache.X509WorkloadUpdate) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.x509 = update
}

func (m *statsFakeManager) getX509Update() *cache.X509WorkloadUpdate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.x509
}

func (m *statsFakeManager) Subscribers() int {
	return int(m.subscribers.Load())
}

func (m *statsFakeManager) CacheStats() cache.StatsReporter {
	return m.stats
}

func (m *statsFakeManager) GetCacheStats() []cache.StatsRow {
	return m.stats.Snapshot()
}

func (m *statsFakeManager) MatchingRegistrationEntries([]*common.Selector) []*common.RegistrationEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.entries
}

func (m *statsFakeManager) FetchWorkloadUpdate([]*common.Selector) *cache.X509WorkloadUpdate {
	return m.getX509Update()
}

func (m *statsFakeManager) FetchJWTSVID(_ context.Context, entry *common.RegistrationEntry, _ []string) (*client.JWTSVID, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return &client.JWTSVID{Token: m.jwtTokens[entry.SpiffeId]}, nil
}

func (m *statsFakeManager) SubscribeToX509CacheChanges(context.Context, cache.Selectors) (cache.Subscriber[cache.X509WorkloadUpdate], error) {
	return newStatsFakeSubscriber(m, m.getX509Update()), nil
}

func (m *statsFakeManager) SubscribeToWITCacheChanges(context.Context, cache.Selectors) (cache.Subscriber[cache.WITWorkloadUpdate], error) {
	m.mu.RLock()
	update := m.wit
	m.mu.RUnlock()
	return newStatsFakeSubscriber(m, update), nil
}

type statsFakeSubscriber[T any] struct {
	m      *statsFakeManager
	ch     chan *T
	cancel context.CancelFunc
}

func newStatsFakeSubscriber[T any](m *statsFakeManager, update *T) *statsFakeSubscriber[T] {
	_, cancel := context.WithCancel(context.Background()) //nolint:gosec // cancel is owned by Finish
	ch := make(chan *T, 1)
	if update != nil {
		ch <- update
	}
	s := &statsFakeSubscriber[T]{m: m, ch: ch, cancel: cancel}
	m.subscribers.Add(1)
	return s
}

func (s *statsFakeSubscriber[T]) Updates() <-chan *T { return s.ch }

func (s *statsFakeSubscriber[T]) Finish() {
	s.cancel()
	s.m.subscribers.Add(-1)
}

type statsFakeAttestor struct{}

func (statsFakeAttestor) Attest(context.Context) ([]*common.Selector, error) {
	return nil, nil
}

func startStatsHandlerServer(t *testing.T, mgr *statsFakeManager) workloadPB.SpiffeWorkloadAPIClient {
	t.Helper()
	log, _ := test.NewNullLogger()
	handler := workload.New(workload.Config{
		TrustDomain: td,
		Manager:     mgr,
		Attestor:    statsFakeAttestor{},
	})

	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		workloadPB.RegisterSpiffeWorkloadAPIServer(s, handler)
	}, grpctest.Middleware(
		middleware.WithLogger(log),
		middleware.Preprocess(func(ctx context.Context, _ string, _ any) (context.Context, error) {
			return rpccontext.WithCallerPID(ctx, 0), nil
		}),
	), grpctest.OverUDS())

	return workloadPB.NewSpiffeWorkloadAPIClient(server.NewGRPCClient(t))
}

func newStatsFakeManager(ca *testca.CA) *statsFakeManager {
	id := spiffeid.RequireFromPath(td, "/workload")
	svid := ca.CreateX509SVID(id)
	return &statsFakeManager{
		stats:     cache.NewStats(nil),
		jwtTokens: make(map[string]string),
		x509: &cache.X509WorkloadUpdate{
			Bundle: ca.Bundle(),
			Identities: []cache.X509Identity{{
				Entry:      &common.RegistrationEntry{EntryId: "id0", SpiffeId: id.String()},
				SVID:       svid.Certificates,
				PrivateKey: svid.PrivateKey,
			}},
		},
		entries: []*common.RegistrationEntry{{EntryId: "id0", SpiffeId: id.String()}},
	}
}

func statRow(t *testing.T, mgr *statsFakeManager, trustDomain, svidType, reason string) cache.StatsRow {
	t.Helper()
	for _, row := range mgr.GetCacheStats() {
		if row.TrustDomain == trustDomain && row.SVIDType == svidType && row.Reason == reason {
			return row
		}
	}
	require.Failf(t, "stat row not found", "trustDomain=%q svidType=%q reason=%q rows=%+v",
		trustDomain, svidType, reason, mgr.GetCacheStats())
	return cache.StatsRow{}
}

// TestWorkloadHandlerX509HitsRecorded ensures a delivered X509 SVID response
// records a cache hit for the identity trust domain.
func TestWorkloadHandlerX509HitsRecorded(t *testing.T) {
	ca := testca.New(t, td)
	mgr := newStatsFakeManager(ca)
	client := startStatsHandlerServer(t, mgr)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	stream, err := client.FetchX509SVID(ctx, &workloadPB.X509SVIDRequest{})
	require.NoError(t, err)
	resp, err := stream.Recv()
	require.NoError(t, err)
	require.Len(t, resp.Svids, 1)

	row := statRow(t, mgr, td.Name(), cache.StatsSVIDTypeX509, cache.ReasonHit)
	assert.Equal(t, int64(1), row.Hits)
}

// TestWorkloadHandlerJWTHitsRecorded ensures delivered JWT SVID and JWT
// bundle responses record cache hits keyed by trust domain.
func TestWorkloadHandlerJWTHitsRecorded(t *testing.T) {
	ca := testca.New(t, td)
	mgr := newStatsFakeManager(ca)
	federatedTD := spiffeid.RequireTrustDomainFromString("federated.test")

	// Two entries in different trust domains.
	id1 := spiffeid.RequireFromPath(td, "/one")
	id2 := spiffeid.RequireFromPath(federatedTD, "/two")
	mgr.entries = []*common.RegistrationEntry{
		{EntryId: "id1", SpiffeId: id1.String()},
		{EntryId: "id2", SpiffeId: id2.String()},
	}
	mgr.jwtTokens[id1.String()] = ca.CreateJWTSVID(id1, []string{"foo"}).Marshal()
	mgr.jwtTokens[id2.String()] = ca.CreateJWTSVID(id2, []string{"foo"}).Marshal()
	mgr.x509 = &cache.X509WorkloadUpdate{
		Bundle:           ca.Bundle(),
		FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{federatedTD: testca.New(t, federatedTD).Bundle()},
		// JWT bundle responses require the caller to have an identity.
		Identities: mgr.x509.Identities,
	}
	client := startStatsHandlerServer(t, mgr)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	// Unary JWT SVID fetch records one hit per trust domain.
	resp, err := client.FetchJWTSVID(ctx, &workloadPB.JWTSVIDRequest{Audience: []string{"foo"}})
	require.NoError(t, err)
	require.Len(t, resp.Svids, 2)

	assert.Equal(t, int64(1), statRow(t, mgr, td.Name(), cache.StatsSVIDTypeJWT, cache.ReasonHit).Hits)
	assert.Equal(t, int64(1), statRow(t, mgr, federatedTD.Name(), cache.StatsSVIDTypeJWT, cache.ReasonHit).Hits)

	// A JWT bundle response records hits for the own and federated bundles.
	bundleStream, err := client.FetchJWTBundles(ctx, &workloadPB.JWTBundlesRequest{})
	require.NoError(t, err)
	_, err = bundleStream.Recv()
	require.NoError(t, err)

	assert.Equal(t, int64(2), statRow(t, mgr, td.Name(), cache.StatsSVIDTypeJWT, cache.ReasonHit).Hits)
	assert.Equal(t, int64(2), statRow(t, mgr, federatedTD.Name(), cache.StatsSVIDTypeJWT, cache.ReasonHit).Hits)
}

// TestWorkloadHandlerWatchReleasesSubscriptionOnDisconnectAndReconnect
// ensures that when a watch client disconnects its cache subscription is
// released, that a subsequent reconnect works, and that the reconnected
// stream receives the fresh state (without a stale federated bundle).
func TestWorkloadHandlerWatchReleasesSubscriptionOnDisconnectAndReconnect(t *testing.T) {
	ca := testca.New(t, td)
	federatedCA := testca.New(t, td2)
	mgr := newStatsFakeManager(ca)
	// Reuse the complete identity (including the private key) across updates
	// so the SVID can be serialized on every stream.
	identity := mgr.getX509Update().Identities[0]

	// Initial state carries a federated bundle.
	mgr.setX509Update(&cache.X509WorkloadUpdate{
		Bundle: ca.Bundle(),
		FederatedBundles: map[spiffeid.TrustDomain]*spiffebundle.Bundle{
			td2: federatedCA.Bundle(),
		},
		Identities: []cache.X509Identity{identity},
	})
	client := startStatsHandlerServer(t, mgr)

	// First stream receives the update with the federated bundle.
	ctx1, cancel1 := context.WithCancel(context.Background())
	stream1, err := client.FetchX509SVID(ctx1, &workloadPB.X509SVIDRequest{})
	require.NoError(t, err)
	resp1, err := stream1.Recv()
	require.NoError(t, err)
	require.Contains(t, resp1.FederatedBundles, td2.IDString())
	require.Equal(t, 1, mgr.Subscribers())

	// Watch client disconnects: the cache subscription must be released.
	cancel1()
	_, _ = stream1.Recv()
	require.Eventually(t, func() bool { return mgr.Subscribers() == 0 },
		5*time.Second, 10*time.Millisecond, "subscription was not released after disconnect")

	// Cache state changes while the client is away: the federated bundle is
	// invalidated.
	mgr.setX509Update(&cache.X509WorkloadUpdate{
		Bundle:     ca.Bundle(),
		Identities: []cache.X509Identity{identity},
	})

	// Reconnect: a fresh subscription must serve the current state, which no
	// longer carries the old federated bundle.
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Minute)
	defer cancel2()
	stream2, err := client.FetchX509SVID(ctx2, &workloadPB.X509SVIDRequest{})
	require.NoError(t, err)
	resp2, err := stream2.Recv()
	require.NoError(t, err)
	assert.NotContains(t, resp2.FederatedBundles, td2.IDString(),
		"the reconnected stream must not receive the invalidated bundle")
	require.Len(t, resp2.Svids, 1)
	require.Equal(t, 1, mgr.Subscribers())
}
