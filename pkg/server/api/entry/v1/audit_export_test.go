package entry_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/audit"
	entryv1 "github.com/spiffe/spire/pkg/server/api/entry/v1"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/pkg/server/registration"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakedatastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type exportServiceTest struct {
	svc  *entryv1.Service
	ds   datastore.DataStore
	ef   *entryFetcher
	log  logrus.FieldLogger
	hook *test.Hook
}

func setupExportServiceTest(t *testing.T) *exportServiceTest {
	t.Helper()
	ds := fakedatastore.New(t)
	ef := &entryFetcher{}
	svc := entryv1.New(entryv1.Config{
		TrustDomain:  td,
		DataStore:    ds,
		EntryFetcher: ef,
	})
	log, hook := test.NewNullLogger()
	return &exportServiceTest{
		svc:  svc,
		ds:   ds,
		ef:   ef,
		log:  log,
		hook: hook,
	}
}

func (e *exportServiceTest) contextWithCaller(caller spiffeid.ID) context.Context {
	requestCtx := rpccontext.WithLogger(context.Background(), e.log)
	requestCtx = rpccontext.WithAuditLog(requestCtx, audit.New(e.log))
	if caller.IsZero() {
		return requestCtx
	}
	return rpccontext.WithCallerID(requestCtx, caller)
}

func createExportTestEntry(t *testing.T, ctx context.Context, ds datastore.DataStore, suffix string, selectors []*common.Selector) *common.RegistrationEntry {
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

func authorizeAllEntries(t *testing.T, ctx context.Context, ds datastore.DataStore, ef *entryFetcher) {
	t.Helper()
	list, err := ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{})
	require.NoError(t, err)
	entries := make([]*types.Entry, 0, len(list.Entries))
	for _, regEntry := range list.Entries {
		protoEntry, err := api.RegistrationEntryToProto(regEntry)
		require.NoError(t, err)
		entries = append(entries, protoEntry)
	}
	ef.entries = entries
}

func walkAPIAuditExport(t *testing.T, ctx context.Context, svc *entryv1.Service, pageSize int32) []*registration.AuditEntryRecord {
	t.Helper()
	req := &registration.AuditExportRequest{PageSize: pageSize}
	var records []*registration.AuditEntryRecord
	for {
		resp, err := svc.ExportAuditEntries(ctx, req)
		require.NoError(t, err)
		records = append(records, resp.Records...)
		if resp.NextPageToken == "" {
			return records
		}
		req.PageToken = resp.NextPageToken
	}
}

func TestExportAuditEntriesFiltersByPermission(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)

	var entries []*common.RegistrationEntry
	for i := range 6 {
		entries = append(entries, createExportTestEntry(t, ctx, e.ds, suffixInt(i), nil))
	}

	// The caller is only authorized for two entries.
	e.ef.entries = []*types.Entry{
		{Id: entries[1].EntryId},
		{Id: entries[4].EntryId},
	}

	records := walkAPIAuditExport(t, ctx, e.svc, 1)
	require.Len(t, records, 2)

	gotIDs := map[string]struct{}{}
	for _, record := range records {
		gotIDs[record.EntryID] = struct{}{}
		assert.Equal(t, agentID.String(), record.Operator)
		assert.NotEmpty(t, record.SelectorSummary)
	}
	assert.Equal(t, map[string]struct{}{
		entries[1].EntryId: {},
		entries[4].EntryId: {},
	}, gotIDs)
}

func TestExportAuditEntriesRequiresCaller(t *testing.T) {
	e := setupExportServiceTest(t)
	createExportTestEntry(t, ctx, e.ds, "one", nil)

	_, err := e.svc.ExportAuditEntries(e.contextWithCaller(spiffeid.ID{}), &registration.AuditExportRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestExportAuditEntriesRejectsNilRequest(t *testing.T) {
	e := setupExportServiceTest(t)
	_, err := e.svc.ExportAuditEntries(e.contextWithCaller(agentID), nil)
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestExportAuditEntriesForcesServerTrustDomainAndOperator(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)
	entry := createExportTestEntry(t, ctx, e.ds, "td", nil)
	e.ef.entries = []*types.Entry{{Id: entry.EntryId}}

	// Attempts to spoof the trust domain and operator are overridden by the
	// service with the authoritative values.
	req := &registration.AuditExportRequest{
		TrustDomain: spiffeid.RequireTrustDomainFromString("spoofed.example"),
		Operator:    spiffeid.RequireFromString("spiffe://spoofed.example/attacker"),
		PageSize:    10,
	}
	resp, err := e.svc.ExportAuditEntries(ctx, req)
	require.NoError(t, err)
	require.Len(t, resp.Records, 1)
	assert.Equal(t, td.Name(), resp.TrustDomain)
	assert.Equal(t, agentID.String(), resp.Operator)
	assert.Equal(t, agentID.String(), resp.Records[0].Operator)

	// The caller's request value was not mutated.
	assert.Equal(t, "spoofed.example", req.TrustDomain.Name())
}

func TestExportAuditEntriesMasksSecretValues(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)

	entry := createExportTestEntry(t, ctx, e.ds, "secret", nil)
	secretValue := "arn:aws:secretsmanager:region:account:secret/db-password-AbCdEf"
	updated, err := e.ds.UpdateRegistrationEntry(ctx, &common.RegistrationEntry{
		EntryId:   entry.EntryId,
		ParentId:  entry.ParentId,
		SpiffeId:  entry.SpiffeId,
		Selectors: entry.Selectors,
		Hint:      secretValue,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, secretValue, updated.Hint)

	e.ef.entries = []*types.Entry{{Id: entry.EntryId}}

	resp, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{})
	require.NoError(t, err)
	require.Len(t, resp.Records, 1)
	record := resp.Records[0]
	assert.Equal(t, "[REDACTED]", record.Hint)
	assert.NotContains(t, record.Hint, secretValue)
	assert.NotContains(t, record.SelectorSummary, secretValue)
	assert.NotContains(t, record.SpiffeID, secretValue)

	// The stored entry must still carry its hint; the export did not mutate it.
	fetched, err := e.ds.FetchRegistrationEntries(ctx, []string{entry.EntryId})
	require.NoError(t, err)
	assert.Equal(t, secretValue, fetched[entry.EntryId].Hint)
}

func TestExportAuditEntriesSnapshotRejectsOtherOperator(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)

	entries := make([]*common.RegistrationEntry, 0, 3)
	for i := range 3 {
		entries = append(entries, createExportTestEntry(t, ctx, e.ds, suffixInt(i), nil))
	}
	e.ef.entries = []*types.Entry{
		{Id: entries[0].EntryId},
		{Id: entries[1].EntryId},
		{Id: entries[2].EntryId},
	}

	first, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{PageSize: 1})
	require.NoError(t, err)
	require.NotEmpty(t, first.NextPageToken)

	otherCaller := spiffeid.RequireFromString("spiffe://example.org/other-operator")
	otherCtx := e.contextWithCaller(otherCaller)
	_, err = e.svc.ExportAuditEntries(otherCtx, &registration.AuditExportRequest{
		PageSize:  1,
		PageToken: first.NextPageToken,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// The owning operator can continue paging.
	second, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{
		PageSize:  1,
		PageToken: first.NextPageToken,
	})
	require.NoError(t, err)
	assert.Len(t, second.Records, 1)
}

func TestExportAuditEntriesLargeBatch(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)

	const total = 150
	for i := range total {
		createExportTestEntry(t, ctx, e.ds, suffixInt(i), nil)
	}
	authorizeAllEntries(t, ctx, e.ds, e.ef)

	records := walkAPIAuditExport(t, ctx, e.svc, 30)
	require.Len(t, records, total)

	seen := map[string]struct{}{}
	for _, record := range records {
		assert.Equal(t, agentID.String(), record.Operator)
		_, dup := seen[record.EntryID]
		assert.False(t, dup, "duplicate record: %s", record.EntryID)
		seen[record.EntryID] = struct{}{}
	}
}

func TestExportAuditEntriesSnapshotStableUnderConcurrentUpdates(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)

	const total = 30
	entries := make([]*common.RegistrationEntry, 0, total)
	for i := range total {
		entries = append(entries, createExportTestEntry(t, ctx, e.ds, suffixInt(i), nil))
	}
	authorizeAllEntries(t, ctx, e.ds, e.ef)

	first, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{PageSize: 7})
	require.NoError(t, err)
	require.Len(t, first.Records, 7)

	// After the snapshot is taken, update every entry (bumping revisions)
	// while walking the remaining pages.
	done := make(chan struct{})
	go func() {
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
			}
			entry := entries[i%len(entries)]
			fetched, fetchErr := e.ds.FetchRegistrationEntries(ctx, []string{entry.EntryId})
			if fetchErr != nil || fetched[entry.EntryId] == nil {
				continue
			}
			updated := fetched[entry.EntryId]
			updated.Hint = "concurrent"
			_, _ = e.ds.UpdateRegistrationEntry(ctx, updated, nil)
		}
	}()

	token := first.NextPageToken
	records := append([]*registration.AuditEntryRecord{}, first.Records...)
	for token != "" {
		page, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{
			PageSize:  7,
			PageToken: token,
		})
		require.NoError(t, err)
		records = append(records, page.Records...)
		token = page.NextPageToken
	}
	close(done)

	require.Len(t, records, total)
	for _, record := range records {
		// All snapshots were taken before the updates; revisions must still
		// be the creation revision.
		assert.Equal(t, int64(0), record.RevisionNumber, "record %s changed during paging", record.EntryID)
	}
}

func TestExportAuditEntriesFetcherError(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)
	entry := createExportTestEntry(t, ctx, e.ds, "boom", nil)
	e.ef.entries = []*types.Entry{{Id: entry.EntryId}}
	e.ef.err = "authorization unavailable"

	_, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestExportAuditEntriesTimeRange(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)
	entry := createExportTestEntry(t, ctx, e.ds, "time", nil)
	e.ef.entries = []*types.Entry{{Id: entry.EntryId}}

	resp, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{
		CreatedAfter: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	assert.Empty(t, resp.Records)
	assert.Empty(t, resp.NextPageToken)
	assert.Equal(t, td.Name(), resp.TrustDomain)
}

func TestExportAuditEntriesAuditLogged(t *testing.T) {
	e := setupExportServiceTest(t)
	ctx := e.contextWithCaller(agentID)
	entry := createExportTestEntry(t, ctx, e.ds, "logged", nil)
	e.ef.entries = []*types.Entry{{Id: entry.EntryId}}

	_, err := e.svc.ExportAuditEntries(ctx, &registration.AuditExportRequest{})
	require.NoError(t, err)

	var found bool
	for _, logEntry := range e.hook.AllEntries() {
		if logEntry.Message != "API accessed" {
			continue
		}
		if logEntry.Data[telemetry.TrustDomain] == td.Name() && logEntry.Data[telemetry.Status] == "success" {
			found = true
		}
	}
	assert.True(t, found, "expected success audit log with trust domain field, got: %#v", e.hook.AllEntries())
}

func suffixInt(i int) string {
	return fmt.Sprintf("%03d", i)
}
