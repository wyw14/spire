package cache

import (
	"sync"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStatsRecordAndSnapshot(t *testing.T) {
	td1 := spiffeid.RequireTrustDomainFromString("domain.test")
	td2 := spiffeid.RequireTrustDomainFromString("otherdomain.test")

	stats := NewStats(nil)

	// two hits for the same key aggregate
	stats.RecordHit(td1, StatsSVIDTypeX509)
	stats.RecordHit(td1, StatsSVIDTypeX509)
	// an eviction for another trust domain and reason
	stats.RecordEviction(td2, StatsSVIDTypeJWT, ReasonTainted, 2)
	// a non-positive eviction is ignored
	stats.RecordEviction(td2, StatsSVIDTypeJWT, ReasonTainted, 0)
	// waiters gauge goes up and down
	stats.AddWaiters(td1, StatsSVIDTypeX509, ReasonMiss, 3)
	stats.AddWaiters(td1, StatsSVIDTypeX509, ReasonMiss, -1)
	stats.AddWaiters(td1, StatsSVIDTypeX509, ReasonMiss, -1)

	rows := stats.Snapshot()
	require.Equal(t, []StatsRow{
		{
			StatsKey: StatsKey{TrustDomain: "domain.test", SVIDType: "X509", Reason: ReasonHit},
			Hits:     2,
		},
		{
			StatsKey: StatsKey{TrustDomain: "domain.test", SVIDType: "X509", Reason: ReasonMiss},
			Waiters:  1,
		},
		{
			StatsKey:  StatsKey{TrustDomain: "otherdomain.test", SVIDType: "JWT", Reason: ReasonTainted},
			Evictions: 2,
		},
	}, rows)
}

func TestStatsSnapshotIsSortedAndStable(t *testing.T) {
	td1 := spiffeid.RequireTrustDomainFromString("aaa.test")
	td2 := spiffeid.RequireTrustDomainFromString("zzz.test")

	stats := NewStats(nil)
	stats.RecordEviction(td2, StatsSVIDTypeX509, ReasonTainted, 1)
	stats.RecordHit(td1, StatsSVIDTypeX509)
	stats.RecordEviction(td1, StatsSVIDTypeX509, ReasonEvicted, 1)
	stats.AddWaiters(td1, StatsSVIDTypeJWT, ReasonMiss, 1)

	first := stats.Snapshot()
	second := stats.Snapshot()

	require.Len(t, first, 4)
	assert.Equal(t, "aaa.test", first[0].TrustDomain)
	assert.Equal(t, "JWT", first[0].SVIDType)
	assert.Equal(t, "aaa.test", first[1].TrustDomain)
	assert.Equal(t, "X509", first[1].SVIDType)
	assert.Equal(t, ReasonEvicted, first[1].Reason)
	// snapshot is a copy: taking another one returns identical values
	assert.Equal(t, first, second)
}

func TestStatsWaitersGaugeNeverNegative(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	stats := NewStats(nil)

	stats.AddWaiters(td, StatsSVIDTypeJWT, ReasonMiss, -2)
	rows := stats.Snapshot()
	require.Len(t, rows, 1)
	assert.Equal(t, int64(0), rows[0].Waiters)
}

func TestStatsConcurrent(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	stats := NewStats(nil)

	const goroutines = 16
	const iterations = 200

	var wg sync.WaitGroup
	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				stats.RecordHit(td, StatsSVIDTypeX509)
				stats.RecordEviction(td, StatsSVIDTypeJWT, ReasonExpired, 1)
				stats.AddWaiters(td, StatsSVIDTypeX509, ReasonMiss, 1)
				stats.AddWaiters(td, StatsSVIDTypeX509, ReasonMiss, -1)
				_ = stats.Snapshot()
			}
		}()
	}
	wg.Wait()

	rows := stats.Snapshot()
	byKey := make(map[StatsKey]StatsRow, len(rows))
	for _, row := range rows {
		byKey[row.StatsKey] = row
	}

	assert.Equal(t, int64(goroutines*iterations), byKey[StatsKey{
		TrustDomain: "domain.test", SVIDType: "X509", Reason: ReasonHit,
	}].Hits)
	assert.Equal(t, int64(goroutines*iterations), byKey[StatsKey{
		TrustDomain: "domain.test", SVIDType: "JWT", Reason: ReasonExpired,
	}].Evictions)
	assert.Equal(t, int64(0), byKey[StatsKey{
		TrustDomain: "domain.test", SVIDType: "X509", Reason: ReasonMiss,
	}].Waiters)
}

func TestNoopStats(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	// must not panic and can be used in place of a real *Stats
	var reporter StatsReporter = NoopStats
	reporter.RecordHit(td, StatsSVIDTypeX509)
	reporter.RecordEviction(td, StatsSVIDTypeX509, ReasonEvicted, 1)
	reporter.AddWaiters(td, StatsSVIDTypeX509, ReasonMiss, 1)
}

func TestStatsReporterOrNoop(t *testing.T) {
	assert.Equal(t, NoopStats, statsReporterOrNoop(nil))
	stats := NewStats(nil)
	var reporter StatsReporter = stats
	assert.Equal(t, reporter, statsReporterOrNoop(stats))
}

func TestTrustDomainFromEntry(t *testing.T) {
	fallback := spiffeid.RequireTrustDomainFromString("fallback.test")

	entry := &common.RegistrationEntry{SpiffeId: "spiffe://other.test/workload"}
	assert.Equal(t, "other.test", trustDomainFromEntry(entry, fallback).Name())

	assert.Equal(t, "spiffe://fallback.test", trustDomainFromEntry(nil, fallback).IDString())
	assert.Equal(t, "spiffe://fallback.test",
		trustDomainFromEntry(&common.RegistrationEntry{SpiffeId: "spiffe://"}, fallback).IDString())
}
