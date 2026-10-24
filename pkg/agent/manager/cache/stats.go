package cache

import (
	"sort"
	"sync"
	"sync/atomic"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
	agentmetrics "github.com/spiffe/spire/pkg/common/telemetry/agent"
	"github.com/spiffe/spire/proto/spire/common"
)

// SVID types tracked by the workload API response cache statistics.
const (
	StatsSVIDTypeX509 = agentmetrics.SVIDTypeX509
	StatsSVIDTypeJWT  = "JWT"
	StatsSVIDTypeWIT  = agentmetrics.SVIDTypeWIT
)

// Refresh/invalidation reasons tracked by the workload API response cache
// statistics.
const (
	// ReasonHit tags a response served from the cache.
	ReasonHit = "hit"
	// ReasonMiss tags a waiter blocked until a missing SVID is minted.
	ReasonMiss = "miss"
	// ReasonExpired tags an SVID invalidated because it is expired/expiring.
	ReasonExpired = "expired"
	// ReasonEntryUpdated tags an SVID invalidated because its registration
	// entry was revised.
	ReasonEntryUpdated = "entry_updated"
	// ReasonEntryRemoved tags an SVID removed together with its registration
	// entry.
	ReasonEntryRemoved = "entry_removed"
	// ReasonEvicted tags an SVID evicted by the LRU size limit (or, for JWT,
	// the hard cache size limit).
	ReasonEvicted = "evicted"
	// ReasonTainted tags an SVID invalidated by a tainted authority.
	ReasonTainted = "tainted"
	// ReasonPrefetch tags a proactive fill of an otherwise unreferenced SVID.
	ReasonPrefetch = "prefetch"
)

// StatsKey identifies a statistics row by trust domain, SVID type and the
// reason the cache entry was interacted with.
type StatsKey struct {
	TrustDomain string
	SVIDType    string
	Reason      string
}

// StatsRow is a point-in-time copy of the counters for a given key.
type StatsRow struct {
	StatsKey

	// Hits is the cumulative number of responses served from the cache.
	Hits int64
	// Evictions is the cumulative number of SVIDs invalidated/evicted.
	Evictions int64
	// Waiters is the current number of callers blocked waiting for the cache
	// to be filled.
	Waiters int64
}

// StatsReporter is the write side of the workload API response cache
// statistics. Implementations must be safe for concurrent use.
type StatsReporter interface {
	// RecordHit records one response served from the cache.
	RecordHit(trustDomain spiffeid.TrustDomain, svidType string)
	// RecordEviction records one or more SVIDs invalidated/evicted for the
	// given reason.
	RecordEviction(trustDomain spiffeid.TrustDomain, svidType, reason string, count int64)
	// AddWaiters adjusts the number of callers currently waiting for the
	// cache to be filled for the given reason. Pass a negative delta when a
	// waiter stops waiting (served, failed or canceled).
	AddWaiters(trustDomain spiffeid.TrustDomain, svidType, reason string, delta int64)
}

// NoopStats discards every reported event.
var NoopStats StatsReporter = noopStats{}

type noopStats struct{}

func (noopStats) RecordHit(spiffeid.TrustDomain, string)                     {}
func (noopStats) RecordEviction(spiffeid.TrustDomain, string, string, int64) {}
func (noopStats) AddWaiters(spiffeid.TrustDomain, string, string, int64)     {}

// Stats collects workload API response cache statistics: hits, evictions and
// the current number of waiters, keyed by trust domain, SVID type and reason.
// It also mirrors the counters to the configured telemetry sink so that they
// can be scraped by operators.
type Stats struct {
	metrics telemetry.Metrics

	counters sync.Map // StatsKey -> *statsCounters
}

// Compile-time assertion that Stats is a StatsReporter.
var _ StatsReporter = (*Stats)(nil)

type statsCounters struct {
	hits      atomic.Int64
	evictions atomic.Int64
	waiters   atomic.Int64
}

// NewStats creates a new statistics collector. Metrics may be nil, in which
// case events are only kept in the in-memory counters.
func NewStats(metrics telemetry.Metrics) *Stats {
	return &Stats{metrics: metrics}
}

func (s *Stats) countersFor(key StatsKey) *statsCounters {
	counters, _ := s.counters.LoadOrStore(key, &statsCounters{})
	return counters.(*statsCounters)
}

// RecordHit records one response served from the cache.
func (s *Stats) RecordHit(trustDomain spiffeid.TrustDomain, svidType string) {
	key := StatsKey{TrustDomain: trustDomain.Name(), SVIDType: svidType, Reason: ReasonHit}
	s.countersFor(key).hits.Add(1)
	agentmetrics.IncrementCacheResponseHits(s.metrics, trustDomain, svidType, ReasonHit, 1)
}

// RecordEviction records one or more SVIDs invalidated/evicted for the given
// reason. Non-positive counts are ignored.
func (s *Stats) RecordEviction(trustDomain spiffeid.TrustDomain, svidType, reason string, count int64) {
	if count <= 0 {
		return
	}
	key := StatsKey{TrustDomain: trustDomain.Name(), SVIDType: svidType, Reason: reason}
	counters := s.countersFor(key)
	counters.evictions.Add(count)
	agentmetrics.IncrementCacheResponseEvictions(s.metrics, trustDomain, svidType, reason, int(count))
}

// AddWaiters adjusts the current number of callers waiting for the cache to
// be filled for the given reason and emits the resulting gauge.
func (s *Stats) AddWaiters(trustDomain spiffeid.TrustDomain, svidType, reason string, delta int64) {
	if delta == 0 {
		return
	}
	key := StatsKey{TrustDomain: trustDomain.Name(), SVIDType: svidType, Reason: reason}
	counters := s.countersFor(key)
	waiters := counters.waiters.Add(delta)
	if waiters < 0 {
		// A bug elsewhere could drive the gauge below zero, but the stored
		// (and exported) value must never be negative.
		for !counters.waiters.CompareAndSwap(waiters, 0) {
			waiters = counters.waiters.Load()
			if waiters >= 0 {
				break
			}
		}
		waiters = 0
	}
	agentmetrics.SetCacheResponseWaiters(s.metrics, trustDomain, svidType, reason, int(waiters))
}

// Snapshot returns the current counters for every key observed so far, sorted
// by trust domain, SVID type and reason. The returned slice is a copy safe to
// retain and inspect without further synchronization.
func (s *Stats) Snapshot() []StatsRow {
	rows := make([]StatsRow, 0)
	s.counters.Range(func(key, value any) bool {
		statsKey := key.(StatsKey)
		counters := value.(*statsCounters)
		rows = append(rows, StatsRow{
			StatsKey:  statsKey,
			Hits:      counters.hits.Load(),
			Evictions: counters.evictions.Load(),
			Waiters:   counters.waiters.Load(),
		})
		return true
	})
	sort.Slice(rows, func(i, j int) bool {
		switch {
		case rows[i].TrustDomain != rows[j].TrustDomain:
			return rows[i].TrustDomain < rows[j].TrustDomain
		case rows[i].SVIDType != rows[j].SVIDType:
			return rows[i].SVIDType < rows[j].SVIDType
		default:
			return rows[i].Reason < rows[j].Reason
		}
	})
	return rows
}

// statsReporterOrNoop returns the given reporter when non-nil and the no-op
// reporter otherwise.
func statsReporterOrNoop(reporter StatsReporter) StatsReporter {
	if reporter != nil {
		return reporter
	}
	return NoopStats
}

// trustDomainFromEntry returns the trust domain of the entry SPIFFE ID. The
// fallback trust domain is returned when the entry SPIFFE ID cannot be
// parsed.
func trustDomainFromEntry(entry *common.RegistrationEntry, fallback spiffeid.TrustDomain) spiffeid.TrustDomain {
	if entry != nil {
		if id, err := spiffeid.FromString(entry.SpiffeId); err == nil {
			return id.TrustDomain()
		}
	}
	return fallback
}
