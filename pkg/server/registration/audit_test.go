package registration

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/clock"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	exportTD       = spiffeid.RequireTrustDomainFromString("example.org")
	otherExportTD  = spiffeid.RequireTrustDomainFromString("other.example")
	exportOperator = spiffeid.RequireFromString("spiffe://example.org/operator")
	otherOperator  = spiffeid.RequireFromString("spiffe://example.org/other-operator")
)

func newAuditTestExporter(t *testing.T, ds datastore.DataStore, clk *clock.Mock, opts AuditExporterConfig) *AuditExporter {
	t.Helper()
	log, _ := test.NewNullLogger()
	base := AuditExporterConfig{
		DataStore: ds,
		Clock:     clk,
		Log:       log,
	}
	if opts.EnumerationPageSize != 0 {
		base.EnumerationPageSize = opts.EnumerationPageSize
	}
	if opts.SnapshotTTL != 0 {
		base.SnapshotTTL = opts.SnapshotTTL
	}
	if opts.MaxSnapshots != 0 {
		base.MaxSnapshots = opts.MaxSnapshots
	}
	return NewAuditExporter(base)
}

func createExportEntry(t *testing.T, ctx context.Context, ds datastore.DataStore, td spiffeid.TrustDomain, suffix string, selectors []*common.Selector) *common.RegistrationEntry {
	t.Helper()
	if selectors == nil {
		selectors = []*common.Selector{{Type: "unix", Value: "uid:" + suffix}}
	}
	entry, err := ds.CreateRegistrationEntry(ctx, &common.RegistrationEntry{
		ParentId:  spiffeid.RequireFromPath(td, "/parent/"+suffix).String(),
		SpiffeId:  spiffeid.RequireFromPath(td, "/workload/"+suffix).String(),
		Selectors: selectors,
	})
	require.NoError(t, err)
	return entry
}

func exportRequest() *AuditExportRequest {
	return &AuditExportRequest{
		TrustDomain: exportTD,
		Operator:    exportOperator,
	}
}

// walkExport pages through an entire export and returns all records.
func walkExport(t *testing.T, ctx context.Context, exporter *AuditExporter, req *AuditExportRequest, pageSize int32) []*AuditEntryRecord {
	t.Helper()
	var records []*AuditEntryRecord
	req.PageSize = pageSize
	for {
		resp, err := exporter.ExportRegistrationEntries(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.Equal(t, req.TrustDomain.Name(), resp.TrustDomain)
		assert.Equal(t, req.Operator.String(), resp.Operator)
		assert.False(t, resp.SnapshotAt.IsZero())

		records = append(records, resp.Records...)
		if resp.NextPageToken == "" {
			return records
		}
		req.PageToken = resp.NextPageToken
	}
}

func (s *ManagerSuite) TestManagerExportDelegates() {
	ctx := s.T().Context()
	s.m = NewManager(ManagerConfig{
		Clock:     s.clock,
		DataStore: s.ds,
		Log:       s.log,
		Metrics:   s.metrics,
	})
	createExportEntry(s.T(), ctx, s.ds, exportTD, "0", nil)

	resp, err := s.m.ExportRegistrationEntries(ctx, exportRequest())
	s.Require().NoError(err)
	s.Require().Len(resp.Records, 1)
	s.Equal(exportOperator.String(), resp.Records[0].Operator)
}

func TestExportBuildsRedactedRecords(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMockAt(t, time.Unix(1_700_000_000, 0))
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})

	active := createExportEntry(t, ctx, ds, exportTD, "active", []*common.Selector{
		{Type: "unix", Value: "gid:2000"},
		{Type: "unix", Value: "uid:1000"},
		{Type: "k8s", Value: "ns:default"},
	})
	expiringSoon := createExportEntry(t, ctx, ds, exportTD, "expiring", nil)
	expired := createExportEntry(t, ctx, ds, exportTD, "expired", nil)

	secretValue := "vault://secret/production/db-password"
	_, err := ds.UpdateRegistrationEntry(ctx, &common.RegistrationEntry{
		EntryId:   active.EntryId,
		ParentId:  active.ParentId,
		SpiffeId:  active.SpiffeId,
		Selectors: active.Selectors,
		Hint:      secretValue,
		Admin:     true,
	}, nil)
	require.NoError(t, err)

	_, err = ds.UpdateRegistrationEntry(ctx, &common.RegistrationEntry{
		EntryId:     expiringSoon.EntryId,
		ParentId:    expiringSoon.ParentId,
		SpiffeId:    expiringSoon.SpiffeId,
		Selectors:   expiringSoon.Selectors,
		EntryExpiry: clk.Now().Add(time.Hour).Unix(),
	}, nil)
	require.NoError(t, err)

	_, err = ds.UpdateRegistrationEntry(ctx, &common.RegistrationEntry{
		EntryId:     expired.EntryId,
		ParentId:    expired.ParentId,
		SpiffeId:    expired.SpiffeId,
		Selectors:   expired.Selectors,
		EntryExpiry: clk.Now().Add(-time.Minute).Unix(),
	}, nil)
	require.NoError(t, err)

	resp, err := exporter.ExportRegistrationEntries(ctx, exportRequest())
	require.NoError(t, err)
	require.Len(t, resp.Records, 3)

	byID := map[string]*AuditEntryRecord{}
	for _, record := range resp.Records {
		byID[record.EntryID] = record
	}

	activeRecord := byID[active.EntryId]
	require.NotNil(t, activeRecord)
	assert.Equal(t, active.SpiffeId, activeRecord.SpiffeID)
	// The active entry was updated once after creation; the snapshot must
	// reflect the bumped revision.
	assert.Equal(t, int64(1), activeRecord.RevisionNumber)
	assert.Equal(t, exportOperator.String(), activeRecord.Operator)
	// Sorted and deduplicated "type:value" summary.
	assert.Equal(t, "k8s:ns:default,unix:gid:2000,unix:uid:1000", activeRecord.SelectorSummary)
	assert.False(t, activeRecord.Revoked)
	// The secret-bearing hint is redacted and never exported in clear text.
	assert.Equal(t, maskedSecretValue, activeRecord.Hint)
	for _, record := range resp.Records {
		assert.NotContains(t, record.Hint, secretValue)
	}

	expiringRecord := byID[expiringSoon.EntryId]
	require.NotNil(t, expiringRecord)
	assert.False(t, expiringRecord.Revoked)
	assert.Empty(t, expiringRecord.Hint)

	expiredRecord := byID[expired.EntryId]
	require.NotNil(t, expiredRecord)
	assert.True(t, expiredRecord.Revoked)
}

func TestExportFiltersByTrustDomain(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})

	one := createExportEntry(t, ctx, ds, exportTD, "one", nil)
	two := createExportEntry(t, ctx, ds, exportTD, "two", nil)
	createExportEntry(t, ctx, ds, otherExportTD, "three", nil)

	resp, err := exporter.ExportRegistrationEntries(ctx, exportRequest())
	require.NoError(t, err)
	require.Len(t, resp.Records, 2)

	gotIDs := []string{resp.Records[0].EntryID, resp.Records[1].EntryID}
	assert.ElementsMatch(t, []string{one.EntryId, two.EntryId}, gotIDs)
}

// createdAtOverrideDS rewrites entry creation timestamps as returned by
// ListRegistrationEntries, allowing deterministic time range tests without
// sleeping.
type createdAtOverrideDS struct {
	*fakedatastore.DataStore
	createdAt map[string]int64
}

func (d *createdAtOverrideDS) ListRegistrationEntries(ctx context.Context, req *datastore.ListRegistrationEntriesRequest) (*datastore.ListRegistrationEntriesResponse, error) {
	resp, err := d.DataStore.ListRegistrationEntries(ctx, req)
	if err != nil {
		return nil, err
	}
	for _, entry := range resp.Entries {
		if ts, ok := d.createdAt[entry.EntryId]; ok {
			entry.CreatedAt = ts
		}
	}
	return resp, nil
}

func TestExportFiltersByTimeRange(t *testing.T) {
	ctx := context.Background()
	fake := fakedatastore.New(t)
	clk := clock.NewMock(t)

	base := time.Unix(1_700_000_000, 0)
	createdAt := map[string]int64{}
	for i, suffix := range []string{"old", "mid", "new"} {
		entry := createExportEntry(t, ctx, fake, exportTD, suffix, nil)
		createdAt[entry.EntryId] = base.Add(time.Duration(i) * time.Minute).Unix()
	}
	ds := &createdAtOverrideDS{DataStore: fake, createdAt: createdAt}
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})

	entries, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	idBySuffix := map[string]string{}
	for _, entry := range entries.Entries {
		switch {
		case entry.SpiffeId == spiffeid.RequireFromPath(exportTD, "/workload/old").String():
			idBySuffix["old"] = entry.EntryId
		case entry.SpiffeId == spiffeid.RequireFromPath(exportTD, "/workload/mid").String():
			idBySuffix["mid"] = entry.EntryId
		default:
			idBySuffix["new"] = entry.EntryId
		}
	}

	for _, tt := range []struct {
		name   string
		after  time.Time
		before time.Time
		want   []string
	}{
		{name: "no bounds", want: []string{"old", "mid", "new"}},
		{name: "after is inclusive", after: base.Add(time.Minute), want: []string{"mid", "new"}},
		{name: "after excludes older", after: base.Add(2 * time.Minute), want: []string{"new"}},
		{name: "before is exclusive", before: base.Add(2 * time.Minute), want: []string{"old", "mid"}},
		{name: "bounded window", after: base.Add(time.Minute), before: base.Add(2 * time.Minute), want: []string{"mid"}},
		{name: "window in the future", after: base.Add(time.Hour), want: nil},
		{name: "window in the past", before: base.Add(-time.Hour), want: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := exportRequest()
			req.CreatedAfter = tt.after
			req.CreatedBefore = tt.before
			records := walkExport(t, ctx, exporter, req, 2)

			gotSuffixes := make([]string, 0, len(records))
			for _, record := range records {
				for suffix, id := range idBySuffix {
					if id == record.EntryID {
						gotSuffixes = append(gotSuffixes, suffix)
					}
				}
			}
			assert.ElementsMatch(t, tt.want, gotSuffixes)
		})
	}
}

func TestExportInvalidTimeRange(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})

	req := exportRequest()
	req.CreatedAfter = time.Unix(100, 0)
	req.CreatedBefore = time.Unix(99, 0)
	_, err := exporter.ExportRegistrationEntries(ctx, req)
	requireErrorCode(t, err, codes.InvalidArgument)
}

func TestExportPaginationUsesConsistentSnapshot(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{EnumerationPageSize: 4})

	const total = 7
	wantIDs := make([]string, 0, total)
	for i := range total {
		entry := createExportEntry(t, ctx, ds, exportTD, fmt.Sprintf("e%02d", i), nil)
		wantIDs = append(wantIDs, entry.EntryId)
	}

	req := exportRequest()
	req.PageSize = 3
	first, err := exporter.ExportRegistrationEntries(ctx, req)
	require.NoError(t, err)
	require.Len(t, first.Records, 3)
	require.NotEmpty(t, first.NextPageToken)

	// Mutate and delete entries after the snapshot was taken. Subsequent
	// pages must remain unaffected.
	for _, record := range first.Records {
		current, err := ds.FetchRegistrationEntries(ctx, []string{record.EntryID})
		require.NoError(t, err)
		updated := current[record.EntryID]
		updated.Hint = "changed-after-snapshot"
		_, err = ds.UpdateRegistrationEntry(ctx, updated, nil)
		require.NoError(t, err)
	}

	req.PageToken = first.NextPageToken
	second, err := exporter.ExportRegistrationEntries(ctx, req)
	require.NoError(t, err)
	require.Len(t, second.Records, 3)
	require.NotEmpty(t, second.NextPageToken)
	assert.Equal(t, first.SnapshotAt, second.SnapshotAt)

	_, err = ds.DeleteRegistrationEntry(ctx, first.Records[0].EntryID)
	require.NoError(t, err)
	_, err = ds.DeleteRegistrationEntry(ctx, second.Records[0].EntryID)
	require.NoError(t, err)

	req.PageToken = second.NextPageToken
	third, err := exporter.ExportRegistrationEntries(ctx, req)
	require.NoError(t, err)
	require.Len(t, third.Records, 1)
	assert.Empty(t, third.NextPageToken)

	gotIDs := make([]string, 0, total)
	for _, record := range append(append(first.Records, second.Records...), third.Records...) {
		gotIDs = append(gotIDs, record.EntryID)
		assert.NotEmpty(t, record.Operator)
	}
	assert.Equal(t, wantIDs, gotIDs)

	// The token used to fetch the final page was consumed and cannot be
	// reused.
	req.PageToken = second.NextPageToken
	_, err = exporter.ExportRegistrationEntries(ctx, req)
	requireErrorCode(t, err, codes.InvalidArgument)

	// A fresh export reflects the post-mutation state.
	fresh, err := exporter.ExportRegistrationEntries(ctx, exportRequest())
	require.NoError(t, err)
	require.Len(t, fresh.Records, total-2)
	for _, record := range fresh.Records {
		if record.EntryID == first.Records[1].EntryID {
			assert.Equal(t, int64(1), record.RevisionNumber)
		}
	}
}

func TestExportLargeBatch(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	// Use a small enumeration page size to exercise keyset walk too.
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{EnumerationPageSize: 37})

	const total = 300
	wantIDs := make(map[string]struct{}, total)
	for i := range total {
		entry := createExportEntry(t, ctx, ds, exportTD, fmt.Sprintf("bulk%03d", i), nil)
		wantIDs[entry.EntryId] = struct{}{}
	}

	records := walkExport(t, ctx, exporter, exportRequest(), 64)
	require.Len(t, records, total)

	seen := make(map[string]struct{}, total)
	for _, record := range records {
		_, dup := seen[record.EntryID]
		assert.False(t, dup, "duplicate record %s", record.EntryID)
		seen[record.EntryID] = struct{}{}
	}
	assert.Equal(t, wantIDs, seen)
}

func TestExportSnapshotStableUnderConcurrentUpdates(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})

	const total = 40
	originalRevisions := map[string]int64{}
	for i := range total {
		entry := createExportEntry(t, ctx, ds, exportTD, fmt.Sprintf("c%02d", i), nil)
		originalRevisions[entry.EntryId] = entry.RevisionNumber
	}

	// Take the first page, then hammer the datastore with concurrent updates
	// while paging through the rest of the snapshot.
	req := exportRequest()
	req.PageSize = 7
	first, err := exporter.ExportRegistrationEntries(ctx, req)
	require.NoError(t, err)
	require.Len(t, first.Records, 7)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				suffix := fmt.Sprintf("c%02d", i%total)
				spiffeID := spiffeid.RequireFromPath(exportTD, "/workload/"+suffix).String()
				list, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{BySpiffeID: spiffeID})
				if err != nil || len(list.Entries) == 0 {
					continue
				}
				entry := list.Entries[0]
				entry.Hint = fmt.Sprintf("concurrent-update-%d", i)
				_, _ = ds.UpdateRegistrationEntry(ctx, entry, nil)
			}
		}()
	}

	var records []*AuditEntryRecord
	records = append(records, first.Records...)
	token := first.NextPageToken
	for token != "" {
		pageReq := exportRequest()
		pageReq.PageSize = 7
		pageReq.PageToken = token
		page, err := exporter.ExportRegistrationEntries(ctx, pageReq)
		require.NoError(t, err)
		records = append(records, page.Records...)
		token = page.NextPageToken
	}
	close(stop)
	wg.Wait()

	require.Len(t, records, total)
	for _, record := range records {
		assert.Equal(t, originalRevisions[record.EntryID], record.RevisionNumber,
			"snapshot record revision changed for %s", record.EntryID)
	}
}

// writeTrackingDataStore fails the test if any mutating datastore method is
// invoked during an export.
type writeTrackingDataStore struct {
	*fakedatastore.DataStore
	mutatingCalls int
}

func (d *writeTrackingDataStore) CreateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, error) {
	d.mutatingCalls++
	return d.DataStore.CreateRegistrationEntry(ctx, entry)
}

func (d *writeTrackingDataStore) CreateOrReturnRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry) (*common.RegistrationEntry, bool, error) {
	d.mutatingCalls++
	return d.DataStore.CreateOrReturnRegistrationEntry(ctx, entry)
}

func (d *writeTrackingDataStore) UpdateRegistrationEntry(ctx context.Context, entry *common.RegistrationEntry, mask *common.RegistrationEntryMask) (*common.RegistrationEntry, error) {
	d.mutatingCalls++
	return d.DataStore.UpdateRegistrationEntry(ctx, entry, mask)
}

func (d *writeTrackingDataStore) DeleteRegistrationEntry(ctx context.Context, entryID string) (*common.RegistrationEntry, error) {
	d.mutatingCalls++
	return d.DataStore.DeleteRegistrationEntry(ctx, entryID)
}

func (d *writeTrackingDataStore) PruneRegistrationEntries(ctx context.Context, expiresBefore time.Time) error {
	d.mutatingCalls++
	return d.DataStore.PruneRegistrationEntries(ctx, expiresBefore)
}

func TestExportDoesNotMutateEntries(t *testing.T) {
	ctx := context.Background()
	ds := &writeTrackingDataStore{DataStore: fakedatastore.New(t)}
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{EnumerationPageSize: 3})

	const total = 10
	for i := range total {
		entry := createExportEntry(t, ctx, ds.DataStore, exportTD, fmt.Sprintf("ro%02d", i), nil)
		entry.Hint = "do-not-touch"
		_, err := ds.DataStore.UpdateRegistrationEntry(ctx, entry, nil)
		require.NoError(t, err)
	}

	before, err := ds.DataStore.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)

	records := walkExport(t, ctx, exporter, exportRequest(), 4)
	require.Len(t, records, total)

	after, err := ds.DataStore.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	require.Equal(t, len(before.Entries), len(after.Entries))
	for i := range before.Entries {
		assert.Equal(t, before.Entries[i].RevisionNumber, after.Entries[i].RevisionNumber)
		assert.Equal(t, before.Entries[i].Hint, after.Entries[i].Hint)
	}
	assert.Zero(t, ds.mutatingCalls, "export invoked mutating datastore calls")
}

func TestExportAppliesAuthorizeHook(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})

	var entries []*common.RegistrationEntry
	for i := range 6 {
		entries = append(entries, createExportEntry(t, ctx, ds, exportTD, fmt.Sprintf("auth%02d", i), nil))
	}
	allowed := map[string]struct{}{
		entries[1].EntryId: {},
		entries[3].EntryId: {},
		entries[5].EntryId: {},
	}

	req := exportRequest()
	req.Authorize = func(_ context.Context, candidateIDs []string) (map[string]struct{}, error) {
		assert.Len(t, candidateIDs, 6)
		return allowed, nil
	}
	records := walkExport(t, ctx, exporter, req, 2)
	require.Len(t, records, 3)
	for _, record := range records {
		_, ok := allowed[record.EntryID]
		assert.True(t, ok, "unauthorized record exported: %s", record.EntryID)
	}
}

func TestExportAuthorizeHookError(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})
	createExportEntry(t, ctx, ds, exportTD, "x", nil)

	req := exportRequest()
	req.Authorize = func(context.Context, []string) (map[string]struct{}, error) {
		return nil, status.Error(codes.PermissionDenied, "not allowed")
	}
	_, err := exporter.ExportRegistrationEntries(ctx, req)
	requireErrorCode(t, err, codes.Internal)
}

func TestExportValidation(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	createExportEntry(t, ctx, ds, exportTD, "one", nil)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{})

	t.Run("nil request", func(t *testing.T) {
		_, err := exporter.ExportRegistrationEntries(ctx, nil)
		requireErrorCode(t, err, codes.InvalidArgument)
	})

	t.Run("missing trust domain", func(t *testing.T) {
		req := exportRequest()
		req.TrustDomain = spiffeid.TrustDomain{}
		_, err := exporter.ExportRegistrationEntries(ctx, req)
		requireErrorCode(t, err, codes.InvalidArgument)
	})

	t.Run("missing operator", func(t *testing.T) {
		req := &AuditExportRequest{TrustDomain: exportTD}
		_, err := exporter.ExportRegistrationEntries(ctx, req)
		requireErrorCode(t, err, codes.InvalidArgument)
	})

	t.Run("unknown page token", func(t *testing.T) {
		req := exportRequest()
		req.PageToken = "does-not-exist"
		_, err := exporter.ExportRegistrationEntries(ctx, req)
		requireErrorCode(t, err, codes.InvalidArgument)
	})

	t.Run("operator mismatch", func(t *testing.T) {
		createExportEntry(t, ctx, ds, exportTD, "operator-mismatch", nil)

		firstReq := exportRequest()
		firstReq.PageSize = 1
		first, err := exporter.ExportRegistrationEntries(ctx, firstReq)
		require.NoError(t, err)
		require.NotEmpty(t, first.NextPageToken)

		otherReq := exportRequest()
		otherReq.PageSize = 1
		otherReq.Operator = otherOperator
		otherReq.PageToken = first.NextPageToken
		_, err = exporter.ExportRegistrationEntries(ctx, otherReq)
		requireErrorCode(t, err, codes.PermissionDenied)

		// The token still works for the owning operator.
		ownerReq := exportRequest()
		ownerReq.PageSize = 1
		ownerReq.PageToken = first.NextPageToken
		resp, err := exporter.ExportRegistrationEntries(ctx, ownerReq)
		require.NoError(t, err)
		assert.Len(t, resp.Records, 1)
	})

	t.Run("page size is clamped", func(t *testing.T) {
		for i := 1; i <= 3; i++ {
			createExportEntry(t, ctx, ds, exportTD, fmt.Sprintf("clamp%02d", i), nil)
		}
		count, err := ds.CountRegistrationEntries(ctx, &datastore.CountRegistrationEntriesRequest{})
		require.NoError(t, err)

		req := exportRequest()
		req.PageSize = maxExportPageSize + 1
		resp, err := exporter.ExportRegistrationEntries(ctx, req)
		require.NoError(t, err)
		assert.Len(t, resp.Records, int(count))
		assert.Empty(t, resp.NextPageToken)
	})
}

func TestExportSnapshotTTL(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{SnapshotTTL: time.Minute})

	for i := range 3 {
		createExportEntry(t, ctx, ds, exportTD, fmt.Sprintf("ttl%02d", i), nil)
	}

	first, err := exporter.ExportRegistrationEntries(ctx, &AuditExportRequest{
		TrustDomain: exportTD,
		Operator:    exportOperator,
		PageSize:    2,
	})
	require.NoError(t, err)
	require.NotEmpty(t, first.NextPageToken)

	clk.Add(time.Minute)

	_, err = exporter.ExportRegistrationEntries(ctx, &AuditExportRequest{
		TrustDomain: exportTD,
		Operator:    exportOperator,
		PageSize:    2,
		PageToken:   first.NextPageToken,
	})
	requireErrorCode(t, err, codes.InvalidArgument)
}

func TestExportEvictsOldestSnapshot(t *testing.T) {
	ctx := context.Background()
	ds := fakedatastore.New(t)
	clk := clock.NewMock(t)
	exporter := newAuditTestExporter(t, ds, clk, AuditExporterConfig{MaxSnapshots: 2})

	for i := range 3 {
		createExportEntry(t, ctx, ds, exportTD, fmt.Sprintf("evict%02d", i), nil)
	}

	tokens := make([]string, 0, 3)
	for range 3 {
		resp, err := exporter.ExportRegistrationEntries(ctx, &AuditExportRequest{
			TrustDomain: exportTD,
			Operator:    exportOperator,
			PageSize:    1,
		})
		require.NoError(t, err)
		require.NotEmpty(t, resp.NextPageToken)
		tokens = append(tokens, resp.NextPageToken)
		clk.Add(time.Second)
	}

	// The first snapshot must have been evicted; newer ones survive.
	oldestReq := exportRequest()
	oldestReq.PageSize = 1
	oldestReq.PageToken = tokens[0]
	_, err := exporter.ExportRegistrationEntries(ctx, oldestReq)
	requireErrorCode(t, err, codes.InvalidArgument)

	newestReq := exportRequest()
	newestReq.PageSize = 1
	newestReq.PageToken = tokens[2]
	resp, err := exporter.ExportRegistrationEntries(ctx, newestReq)
	require.NoError(t, err)
	assert.Len(t, resp.Records, 1)
}

func TestSummarizeSelectors(t *testing.T) {
	assert.Empty(t, summarizeSelectors(nil))

	summary := summarizeSelectors([]*common.Selector{
		{Type: "unix", Value: "uid:1000"},
		{Type: "unix", Value: "gid:2000"},
		{Type: "k8s", Value: "ns:default"},
		{Type: "unix", Value: "uid:1000"}, // duplicate
		{Type: "unix", Value: "gid:2000"}, // duplicate
	})
	assert.Equal(t, "k8s:ns:default,unix:gid:2000,unix:uid:1000", summary)
}

func requireErrorCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, code, status.Code(err), "unexpected error: %v", err)
}
