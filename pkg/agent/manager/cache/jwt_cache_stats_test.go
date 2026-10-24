package cache

import (
	"context"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/stretchr/testify/assert"
)

// tok1 and tok2 are real, parsable JWT-SVIDs from jwt_cache_test.go (key ids
// keyID1/keyID2). Their subject is spiffe://example.org/agent/dbuser.
func newJWTCacheWithStats(t *testing.T, maxSize int) (*JWTSVIDCache, *Stats) {
	t.Helper()
	stats := NewStats(nil)
	log, _ := test.NewNullLogger()
	return NewJWTSVIDCache(log, telemetry.Blackhole{}, maxSize, stats), stats
}

func TestJWTSVIDCacheStatsEvictionOnOverwrite(t *testing.T) {
	now := time.Now()
	tok1 := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRaRGZZaXcxdUd6TXdkTVlITDdGRVl5SzhIT0tLd0xYIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3MjQzNjU3MzEsImlhdCI6MTcyNDI3OTQwNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvYWdlbnQvZGJ1c2VyIn0.dFr-oWhm5tK0bBuVXt-sGESM5l7hhoY-Gtt5DkuFoJL5Y9d4ZfmicCvUCjL4CqDB3BO_cPqmFfrO7H7pxQbGLg"
	tok2 := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNKMXI5TVY4OTZTWXBMY0RMUjN3Q29QRHprTXpkN25tIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3Mjg1NzEwMjUsImlhdCI6MTcyODU3MDcyNSwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvYWdlbnQvZGJ1c2VyIn0.1YnDj7nknwIHEuNKEN0cNypXKS4SUeILXlNOsOs2XElHzfKhhDcl0sYKYtQc1Itf6cygz9C16VOQ_Yjoos2Qfg"

	cache, stats := newJWTCacheWithStats(t, 4)
	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")

	cache.SetJWTSVID(spiffeID, []string{"bar"}, &client.JWTSVID{Token: tok1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	// a fresh fill does not evict anything
	assert.Empty(t, stats.Snapshot())

	// replacing the expiring token invalidates the previous one
	cache.SetJWTSVID(spiffeID, []string{"bar"}, &client.JWTSVID{Token: tok2, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	row := requireStatRow(t, stats, "example.org", StatsSVIDTypeJWT, ReasonExpired)
	assert.Equal(t, int64(1), row.Evictions)
	assert.Equal(t, 1, cache.CountJWTSVIDs())
}

func TestJWTSVIDCacheStatsEvictionOnCapacity(t *testing.T) {
	now := time.Now()
	tok1 := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRaRGZZaXcxdUd6TXdkTVlITDdGRVl5SzhIT0tLd0xYIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3MjQzNjU3MzEsImlhdCI6MTcyNDI3OTQwNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvYWdlbnQvZGJ1c2VyIn0.dFr-oWhm5tK0bBuVXt-sGESM5l7hhoY-Gtt5DkuFoJL5Y9d4ZfmicCvUCjL4CqDB3BO_cPqmFfrO7H7pxQbGLg"

	cache, stats := newJWTCacheWithStats(t, 2)

	id1 := spiffeid.RequireFromString("spiffe://example.org/one")
	id2 := spiffeid.RequireFromString("spiffe://otherdomain.test/two")
	id3 := spiffeid.RequireFromString("spiffe://example.org/three")
	cache.SetJWTSVID(id1, []string{"audience"}, &client.JWTSVID{Token: tok1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	cache.SetJWTSVID(id2, []string{"audience"}, &client.JWTSVID{Token: tok1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})

	// Nothing evicted yet and overwriting an existing key at capacity must
	// not evict anything.
	cache.SetJWTSVID(id2, []string{"audience"}, &client.JWTSVID{Token: tok1, IssuedAt: now, ExpiresAt: now.Add(2 * time.Minute)})
	expired := requireStatRow(t, stats, "otherdomain.test", StatsSVIDTypeJWT, ReasonExpired)
	assert.Equal(t, int64(1), expired.Evictions)
	assert.Equal(t, 2, cache.CountJWTSVIDs())

	// A third distinct key forces the LRU entry out.
	cache.SetJWTSVID(id3, []string{"audience"}, &client.JWTSVID{Token: tok1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	assert.Equal(t, 2, cache.CountJWTSVIDs())

	var evictedTD string
	for _, row := range stats.Snapshot() {
		if row.Reason == ReasonEvicted {
			assert.Equal(t, int64(1), row.Evictions)
			evictedTD = row.TrustDomain
		}
	}
	assert.NotEmpty(t, evictedTD, "an LRU eviction must be recorded")
	assert.Contains(t, []string{"example.org", "otherdomain.test"}, evictedTD)
}

func TestJWTSVIDCacheStatsEvictionOnTaint(t *testing.T) {
	now := time.Now()
	tok1 := "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRaRGZZaXcxdUd6TXdkTVlITDdGRVl5SzhIT0tLd0xYIiwidHlwIjoiSldUIn0.eyJhdWQiOlsidGVzdC1hdWRpZW5jZSJdLCJleHAiOjE3MjQzNjU3MzEsImlhdCI6MTcyNDI3OTQwNywic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvYWdlbnQvZGJ1c2VyIn0.dFr-oWhm5tK0bBuVXt-sGESM5l7hhoY-Gtt5DkuFoJL5Y9d4ZfmicCvUCjL4CqDB3BO_cPqmFfrO7H7pxQbGLg"

	cache, stats := newJWTCacheWithStats(t, 4)
	spiffeID := spiffeid.RequireFromString("spiffe://example.org/blog")
	cache.SetJWTSVID(spiffeID, []string{"audience-1"},
		&client.JWTSVID{Token: tok1, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})

	cache.TaintJWTSVIDs(context.Background(), map[string]struct{}{"dZDfYiw1uGzMwdMYHL7FEYyK8HOKKwLX": {}})

	assert.Equal(t, 0, cache.CountJWTSVIDs())
	row := requireStatRow(t, stats, "example.org", StatsSVIDTypeJWT, ReasonTainted)
	assert.Equal(t, int64(1), row.Evictions)
}
