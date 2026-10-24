package manager

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/agent/manager/storecache"
	"github.com/spiffe/spire/pkg/agent/workloadkey"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/rotationutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/spiffe/spire/test/fakes/fakeagentkeymanager"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type singleFlightHarness struct {
	m        *manager
	clk      *clock.Mock
	entry    *common.RegistrationEntry
	audience []string
	block    chan struct{}
	calls    *atomic.Int32
}

func newSingleFlightHarness(t *testing.T) *singleFlightHarness {
	t.Helper()

	dir := spiretest.TempDir(t)
	km := fakeagentkeymanager.New(t, dir)

	fetchResp := &svidv1.NewJWTSVIDResponse{}
	clk := clock.NewMock(t)

	block := make(chan struct{})
	calls := &atomic.Int32{}

	api := newMockAPI(t, &mockAPIConfig{
		km: km,
		getAuthorizedEntries: func(*mockAPI, int32, *entryv1.GetAuthorizedEntriesRequest) (*entryv1.GetAuthorizedEntriesResponse, error) {
			return makeGetAuthorizedEntriesResponse(t, "resp1", "resp2"), nil
		},
		batchNewX509SVIDEntries: func(*mockAPI, int32) []*common.RegistrationEntry {
			return makeBatchNewX509SVIDEntries("resp1", "resp2")
		},
		newJWTSVID: func(*mockAPI, *svidv1.NewJWTSVIDRequest) (*svidv1.NewJWTSVIDResponse, error) {
			calls.Add(1)
			<-block
			return fetchResp, nil
		},
		clk:     clk,
		svidTTL: 200,
	})

	cat := fakeagentcatalog.New()
	cat.SetKeyManager(km)

	baseSVID, baseSVIDKey := api.newSVID(joinTokenID, 1*time.Hour)

	c := &Config{
		ServerAddr:       api.addr,
		SVID:             baseSVID,
		SVIDKey:          baseSVIDKey,
		Log:              testLogger,
		TrustDomain:      trustDomain,
		Storage:          openStorage(t, dir),
		Bundle:           api.bundle,
		Metrics:          &telemetry.Blackhole{},
		Catalog:          cat,
		Clk:              clk,
		WorkloadKeyType:  workloadkey.ECP256,
		SVIDStoreCache:   storecache.New(&storecache.Config{TrustDomain: trustDomain, Log: testLogger}),
		RotationStrategy: rotationutil.NewRotationStrategy(0),
	}

	m := newManager(c)
	require.NoError(t, m.Initialize(context.Background()))

	testEntry := regEntriesMap["resp2"][0]
	testEntrySPIFFEID, err := idutil.IDProtoFromString(testEntry.SpiffeId)
	require.NoError(t, err)
	now := clk.Now()
	fetchResp.Svid = &types.JWTSVID{
		Token:     "minted-token",
		Id:        testEntrySPIFFEID,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
	}

	return &singleFlightHarness{
		m:        m,
		clk:      clk,
		entry:    testEntry,
		audience: []string{"foo"},
		block:    block,
		calls:    calls,
	}
}

func waitForJWTWaiters(t *testing.T, m *manager, want int64) {
	t.Helper()
	require.Eventually(t, func() bool {
		for _, row := range m.GetCacheStats() {
			if row.SVIDType == cache.StatsSVIDTypeJWT && row.Reason == cache.ReasonMiss {
				return row.Waiters == want
			}
		}
		return want == 0
	}, 10*time.Second, 5*time.Millisecond, "waiters never reached %d (rows=%+v)", want, m.GetCacheStats())
}

// TestFetchJWTSVIDCoalescesConcurrentFetches ensures concurrent misses for the
// same SPIFFE ID and audience result in a single upstream mint, while the
// coalesced callers are counted as waiters and subsequently served.
func TestFetchJWTSVIDCoalescesConcurrentFetches(t *testing.T) {
	h := newSingleFlightHarness(t)

	const numCallers = 8

	var wg sync.WaitGroup
	resultCh := make(chan string, numCallers)
	errCh := make(chan error, numCallers)
	for range numCallers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			svid, err := h.m.FetchJWTSVID(context.Background(), h.entry, h.audience)
			if err != nil {
				errCh <- err
				return
			}
			resultCh <- svid.Token
		}()
	}

	// One leader is minting; numCallers-1 followers must be parked waiting.
	waitForJWTWaiters(t, h.m, numCallers-1)
	require.Eventually(t, func() bool {
		return h.calls.Load() == 1
	}, 5*time.Second, 10*time.Millisecond, "the leader mint request must reach the server")

	// Serve the leader and let the waiters proceed.
	close(h.block)
	wg.Wait()
	close(resultCh)
	close(errCh)

	require.Empty(t, errCh)
	for token := range resultCh {
		assert.Equal(t, "minted-token", token)
	}
	assert.Equal(t, int32(1), h.calls.Load(), "concurrent misses must be coalesced into one mint")
	waitForJWTWaiters(t, h.m, 0)

	// A subsequent call is a plain cache hit and must not mint again.
	svid, err := h.m.FetchJWTSVID(context.Background(), h.entry, h.audience)
	require.NoError(t, err)
	assert.Equal(t, "minted-token", svid.Token)
	assert.Equal(t, int32(1), h.calls.Load())
}

// TestFetchJWTSVIDWaiterReleasedOnCancel ensures a coalesced caller that goes
// away while waiting releases its waiter count (and does not mint).
func TestFetchJWTSVIDWaiterReleasedOnCancel(t *testing.T) {
	h := newSingleFlightHarness(t)

	// leader
	leaderErr := make(chan error, 1)
	go func() {
		_, err := h.m.FetchJWTSVID(context.Background(), h.entry, h.audience)
		leaderErr <- err
	}()

	// follower that will disconnect before the leader completes
	ctx, cancel := context.WithCancel(context.Background())
	followerErr := make(chan error, 1)
	go func() {
		_, err := h.m.FetchJWTSVID(ctx, h.entry, h.audience)
		followerErr <- err
	}()

	waitForJWTWaiters(t, h.m, 1)
	require.Equal(t, int32(1), h.calls.Load())

	cancel()
	select {
	case err := <-followerErr:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "canceled waiter did not return")
	}

	waitForJWTWaiters(t, h.m, 0)
	require.Equal(t, int32(1), h.calls.Load(), "the canceled waiter must not mint")

	// the leader still completes successfully
	close(h.block)
	select {
	case err := <-leaderErr:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "leader did not complete")
	}
}
