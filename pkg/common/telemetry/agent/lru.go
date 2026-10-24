package agent

import (
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/common/telemetry"
)

func IncrementEntriesAdded(m telemetry.Metrics, entriesAdded int) {
	m.IncrCounter([]string{telemetry.EntryAdded}, float32(entriesAdded))
}

func IncrementEntriesUpdated(m telemetry.Metrics, entriesUpdated int) {
	m.IncrCounter([]string{telemetry.EntryUpdated}, float32(entriesUpdated))
}

func IncrementEntriesRemoved(m telemetry.Metrics, entriesRemoved int) {
	m.IncrCounter([]string{telemetry.EntryRemoved}, float32(entriesRemoved))
}

func SetEntriesMapSize(m telemetry.Metrics, svidType string, recordMapSize int) {
	m.SetGaugeWithLabels([]string{telemetry.RecordMapSize}, float32(recordMapSize), []telemetry.Label{
		{Name: telemetry.SVIDType, Value: svidType},
	})
}

func SetSVIDMapSize(m telemetry.Metrics, svidType string, svidMapSize int) {
	m.SetGaugeWithLabels([]string{telemetry.SVIDMapSize}, float32(svidMapSize), []telemetry.Label{
		{Name: telemetry.SVIDType, Value: svidType},
	})
}

func SetJWTSVIDCacheSize(m telemetry.Metrics, cacheSize int) {
	m.SetGauge([]string{telemetry.JWTSVIDCacheSize}, float32(cacheSize))
}

func cacheResponseLabels(trustDomain spiffeid.TrustDomain, svidType, reason string) []telemetry.Label {
	labels := []telemetry.Label{
		{Name: telemetry.TrustDomainID, Value: trustDomain.Name()},
		{Name: telemetry.SVIDType, Value: svidType},
	}
	if reason != "" {
		labels = append(labels, telemetry.Label{Name: telemetry.Reason, Value: reason})
	}
	return labels
}

// IncrementCacheResponseHits counts workload API responses served from the
// response cache.
func IncrementCacheResponseHits(m telemetry.Metrics, trustDomain spiffeid.TrustDomain, svidType, reason string, count int) {
	if m == nil || count <= 0 {
		return
	}
	m.IncrCounterWithLabels([]string{telemetry.CacheResponseHits}, float32(count),
		cacheResponseLabels(trustDomain, svidType, reason))
}

// IncrementCacheResponseEvictions counts SVIDs invalidated/evicted from the
// response cache for the given reason.
func IncrementCacheResponseEvictions(m telemetry.Metrics, trustDomain spiffeid.TrustDomain, svidType, reason string, count int) {
	if m == nil || count <= 0 {
		return
	}
	m.IncrCounterWithLabels([]string{telemetry.CacheResponseEvictions}, float32(count),
		cacheResponseLabels(trustDomain, svidType, reason))
}

// SetCacheResponseWaiters sets the gauge of callers currently waiting for the
// response cache to be filled for the given reason.
func SetCacheResponseWaiters(m telemetry.Metrics, trustDomain spiffeid.TrustDomain, svidType, reason string, waiters int) {
	if m == nil {
		return
	}
	if waiters < 0 {
		waiters = 0
	}
	m.SetGaugeWithLabels([]string{telemetry.CacheResponseWaiters}, float32(waiters),
		cacheResponseLabels(trustDomain, svidType, reason))
}
