package cache

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestLRUCacheWithStats(t testing.TB) (*X509SVIDLRUCache, *Stats) {
	stats := NewStats(nil)
	log, _ := test.NewNullLogger()
	cache := NewX509LRUCache(X509LRUCacheConfig{
		Log:         log,
		TrustDomain: trustDomain1,
		Bundle:      bundleV1,
		Metrics:     telemetry.Blackhole{},
		Clk:         clock.NewMock(t),
		Stats:       stats,
	})
	return cache, stats
}

func requireStatRow(t *testing.T, stats *Stats, trustDomain, svidType, reason string) StatsRow {
	t.Helper()
	for _, row := range stats.Snapshot() {
		if row.TrustDomain == trustDomain && row.SVIDType == svidType && row.Reason == reason {
			return row
		}
	}
	require.Failf(t, "stat row not found", "trustDomain=%q svidType=%q reason=%q rows=%+v",
		trustDomain, svidType, reason, stats.Snapshot())
	return StatsRow{}
}

func TestLRUCacheStatsHitsOnImmediateSubscription(t *testing.T) {
	cache, stats := newTestLRUCacheWithStats(t)

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(makeX509SVIDs(foo))

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer sub.Finish()
	assertAnyX509WorkloadUpdate(t, sub)

	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonHit)
	assert.Equal(t, int64(1), row.Hits)
	assert.Equal(t, int64(0), row.Waiters)
}

func TestLRUCacheStatsHitsOnBundleOnlySubscriptionAndFetch(t *testing.T) {
	cache, stats := newTestLRUCacheWithStats(t)

	// A subscriber with no selectors is immediately served the cached bundle.
	sub := subscribeToWorkloadUpdates(t, cache, nil)
	defer sub.Finish()
	assertAnyX509WorkloadUpdate(t, sub)

	// A bundle-only fetch (no matching entries) is a hit too.
	cache.FetchWorkloadUpdate(makeSelectors("A"))

	// A fetch with a matching entry but no cached SVID is not a hit.
	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.FetchWorkloadUpdate(makeSelectors("A"))

	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonHit)
	assert.Equal(t, int64(2), row.Hits)

	// Once the SVID is cached, fetches become hits.
	cache.UpdateSVIDs(makeX509SVIDs(foo))
	cache.FetchWorkloadUpdate(makeSelectors("A"))
	row = requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonHit)
	assert.Equal(t, int64(3), row.Hits)
}

func TestLRUCacheStatsWaitersWhileBlockedAndReleasedWhenFilled(t *testing.T) {
	clk := clock.NewMock(t)
	stats := NewStats(nil)
	log, _ := test.NewNullLogger()
	cache := NewX509LRUCache(X509LRUCacheConfig{
		Log:              log,
		TrustDomain:      trustDomain1,
		Bundle:           bundleV1,
		Metrics:          telemetry.Blackhole{},
		SvidCacheMaxSize: 10,
		Clk:              clk,
		Stats:            stats,
	})

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)

	waitCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	go func() {
		sub, err := cache.subscribeToWorkloadUpdates(context.Background(), foo.Selectors, func() {
			waitCh <- struct{}{}
		})
		if err != nil {
			errCh <- err
			return
		}
		defer sub.Finish()
		<-sub.Updates()
		errCh <- nil
	}()

	// The subscriber must be parked waiting for the SVID to be minted.
	select {
	case <-waitCh:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "subscriber never started waiting")
	}
	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonMiss)
	assert.Equal(t, int64(1), row.Waiters, "subscriber should be counted as a waiter")

	// Mint the SVID and let the backoff fire.
	cache.SyncSVIDsWithSubscribers()
	require.Len(t, cache.GetStaleEntries(), 1)
	cache.UpdateSVIDs(makeX509SVIDs(foo))
	clk.WaitForAfter(time.Second, "waiting for after to get called")
	clk.Add(SVIDSyncInterval * 4)

	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "subscriber did not get served")
	}

	// Waiters are released and the served update counts as a hit.
	assert.Eventually(t, func() bool {
		row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonMiss)
		return row.Waiters == 0
	}, 5*time.Second, 10*time.Millisecond)
	row = requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonHit)
	assert.Equal(t, int64(1), row.Hits)
}

func TestLRUCacheStatsWaitersReleasedOnCancelAndSubscriptionDropped(t *testing.T) {
	clk := clock.NewMock(t)
	stats := NewStats(nil)
	log, _ := test.NewNullLogger()
	cache := NewX509LRUCache(X509LRUCacheConfig{
		Log:         log,
		TrustDomain: trustDomain1,
		Bundle:      bundleV1,
		Metrics:     telemetry.Blackhole{},
		Clk:         clk,
		Stats:       stats,
	})

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	waitCh := make(chan struct{}, 1)
	errCh := make(chan error, 1)
	go func() {
		sub, err := cache.subscribeToWorkloadUpdates(ctx, foo.Selectors, func() {
			waitCh <- struct{}{}
		})
		if err != nil {
			errCh <- err
			return
		}
		sub.Finish()
		errCh <- nil
	}()

	select {
	case <-waitCh:
	case <-time.After(10 * time.Second):
		require.FailNow(t, "subscriber never started waiting")
	}
	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonMiss)
	require.Equal(t, int64(1), row.Waiters)

	// Disconnect the client (cancel its context).
	cancel()
	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(10 * time.Second):
		require.FailNow(t, "subscriber did not exit on cancel")
	}

	row = requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonMiss)
	assert.Equal(t, int64(0), row.Waiters, "waiter must be released when the watch client disconnects")
	assert.Equal(t, 0, cache.countMatchingSubscribers(foo, makeSelectorSet(t, foo.Selectors...)),
		"the subscription must be released when the watch client disconnects")
}

func TestLRUCacheStatsEvictionOnEntryRemoved(t *testing.T) {
	cache, stats := newTestLRUCacheWithStats(t)

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(makeX509SVIDs(foo))

	// Remove the registration entry (and its SVID).
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: map[string]*common.RegistrationEntry{},
	}, nil)

	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonEntryRemoved)
	assert.Equal(t, int64(1), row.Evictions)
	assert.Equal(t, 0, cache.CountSVIDs())
}

func TestLRUCacheStatsEvictionOnLRUSize(t *testing.T) {
	clk := clock.NewMock(t)
	stats := NewStats(nil)
	log, _ := test.NewNullLogger()
	cache := NewX509LRUCache(X509LRUCacheConfig{
		Log:              log,
		TrustDomain:      trustDomain1,
		Bundle:           bundleV1,
		Metrics:          telemetry.Blackhole{},
		SvidCacheMaxSize: 1,
		Clk:              clk,
		Stats:            stats,
	})

	foo := makeRegistrationEntry("FOO", "A")
	bar := makeRegistrationEntry("BAR", "B")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)
	cache.UpdateSVIDs(makeX509SVIDs(foo, bar))
	require.Equal(t, 2, cache.CountSVIDs())

	// A subsequent update enforces the soft limit and evicts one SVID.
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo, bar),
	}, nil)

	assert.Equal(t, 1, cache.CountSVIDs())
	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonEvicted)
	assert.Equal(t, int64(1), row.Evictions)
}

func TestLRUCacheStatsEvictionOnExpiry(t *testing.T) {
	cache, stats := newTestLRUCacheWithStats(t)

	foo := makeRegistrationEntry("FOO", "A")
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(makeX509SVIDs(foo))

	// checkSVID reports the cached SVID as expiring.
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, func(_, _ *common.RegistrationEntry, _ *X509SVID) bool {
		return true
	})
	require.Equal(t, map[string]string{foo.EntryId: ReasonExpired}, cache.staleEntries)

	// Replacing the SVID invalidates the previous one for expiry reasons.
	cache.UpdateSVIDs(makeX509SVIDs(foo))

	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonExpired)
	assert.Equal(t, int64(1), row.Evictions)
}

func TestLRUCacheStatsEvictionOnEntryRevision(t *testing.T) {
	cache, stats := newTestLRUCacheWithStats(t)

	foo := makeRegistrationEntry("FOO", "A")
	foo.RevisionNumber = 1
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(makeX509SVIDs(foo))

	// A revised registration entry invalidates the cached SVID.
	revisedFoo := makeRegistrationEntry("FOO", "A")
	revisedFoo.RevisionNumber = 2
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV2),
		RegistrationEntries: makeRegistrationEntries(revisedFoo),
	}, nil)
	require.Equal(t, map[string]string{foo.EntryId: ReasonEntryUpdated}, cache.staleEntries)

	cache.UpdateSVIDs(makeX509SVIDs(revisedFoo))

	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonEntryUpdated)
	assert.Equal(t, int64(1), row.Evictions)
}

func TestLRUCacheStatsEvictionOnTaintedAuthority(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	clk := clock.NewMock(t)
	stats := NewStats(nil)
	log, _ := test.NewNullLogger()
	cache := NewX509LRUCache(X509LRUCacheConfig{
		Log:              log,
		TrustDomain:      trustDomain1,
		Bundle:           bundleV1,
		Metrics:          telemetry.Blackhole{},
		SvidCacheMaxSize: 10,
		Clk:              clk,
		Stats:            stats,
	})
	batchProcessedCh := make(chan struct{}, 1)
	cache.taintedBatchProcessedCh = batchProcessedCh

	entries := createTestEntries(1)
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(entries...),
	}, nil)

	taintedCA := testca.New(t, trustDomain1)
	svids := makeX509SVIDs(entries...)
	prepareSVIDs(t, entries, svids, taintedCA)
	cache.UpdateSVIDs(svids)
	require.Equal(t, 1, cache.CountSVIDs())

	cache.TaintX509SVIDs(ctx, taintedCA.X509Authorities())
	select {
	case <-batchProcessedCh:
	case <-ctx.Done():
		require.FailNow(t, "tainted batch was not processed")
	}

	require.Eventually(t, func() bool { return cache.CountSVIDs() == 0 },
		5*time.Second, 10*time.Millisecond)
	row := requireStatRow(t, stats, trustDomain1.Name(), StatsSVIDTypeX509, ReasonTainted)
	assert.Equal(t, int64(1), row.Evictions)
}

func TestLRUCacheStatsEvictionAttributesOtherTrustDomain(t *testing.T) {
	cache, stats := newTestLRUCacheWithStats(t)

	// Registration entry issued for a SPIFFE ID in another trust domain;
	// eviction stats must be attributed to that trust domain.
	otherTD := spiffeid.RequireTrustDomainFromString("federated.test")
	foo := &common.RegistrationEntry{
		EntryId:     "FOO",
		SpiffeId:    "spiffe://federated.test/FOO",
		Selectors:   makeSelectors("A"),
		X509SvidTtl: defaultX509SVIDTTL,
		JwtSvidTtl:  defaultJwtSVIDTTL,
	}
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(makeX509SVIDs(foo))
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: map[string]*common.RegistrationEntry{},
	}, nil)

	row := requireStatRow(t, stats, otherTD.Name(), StatsSVIDTypeX509, ReasonEntryRemoved)
	assert.Equal(t, int64(1), row.Evictions)
}

// TestLRUCacheRemovedFederatedBundleDoesNotLeak ensures that when a federated
// bundle is invalidated, subscribers are notified with an update that no
// longer carries the old bundle.
func TestLRUCacheRemovedFederatedBundleDoesNotLeak(t *testing.T) {
	cache, _ := newTestLRUCacheWithStats(t)

	foo := makeRegistrationEntry("FOO", "A")
	foo.FederatesWith = makeFederatesWith(otherBundleV1)
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1, otherBundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)
	cache.UpdateSVIDs(makeX509SVIDs(foo))

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer sub.Finish()
	assertX509WorkloadUpdateEqual(t, sub, &X509WorkloadUpdate{
		Bundle:           bundleV1,
		FederatedBundles: makeBundles(otherBundleV1),
		Identities:       []X509Identity{{Entry: foo}},
	})

	// The federated bundle disappears from the server update while the entry
	// still declares federation with that domain.
	cache.UpdateEntries(&UpdateEntries{
		Bundles:             makeBundles(bundleV1),
		RegistrationEntries: makeRegistrationEntries(foo),
	}, nil)

	select {
	case update := <-sub.Updates():
		require.NotNil(t, update)
		assert.Empty(t, update.FederatedBundles,
			"the invalidated federated bundle must not leak into the new workload update")
		assert.NotNil(t, update.Bundle, "the agent trust domain bundle must still be present")
		assert.True(t, update.Bundle.Equal(bundleV1))
		assert.Equal(t, []X509Identity{{Entry: foo}}, update.Identities)
	case <-time.After(time.Minute):
		require.FailNow(t, "subscriber was not notified when the federated bundle was removed")
	}
}

// TestLRUCacheOwnTrustDomainBundleIsNeverDropped ensures the agent trust
// domain bundle survives even when absent from an entries update.
func TestLRUCacheOwnTrustDomainBundleIsNeverDropped(t *testing.T) {
	cache, _ := newTestLRUCacheWithStats(t)

	sub := subscribeToWorkloadUpdates(t, cache, makeSelectors("A"))
	defer sub.Finish()
	assertX509WorkloadUpdateEqual(t, sub, &X509WorkloadUpdate{Bundle: bundleV1})

	cache.UpdateEntries(&UpdateEntries{
		Bundles:             map[spiffeid.TrustDomain]*Bundle{},
		RegistrationEntries: map[string]*common.RegistrationEntry{},
	}, nil)

	update := cache.FetchWorkloadUpdate(makeSelectors("A"))
	require.NotNil(t, update.Bundle)
	assert.True(t, update.Bundle.Equal(bundleV1))
}

func makeSelectorSet(t *testing.T, selectors ...*common.Selector) selectorSet {
	t.Helper()
	set, done := allocSelectorSet(selectors...)
	t.Cleanup(done)
	return set
}
