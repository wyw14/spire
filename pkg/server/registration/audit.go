package registration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire/pkg/server/datastore"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// defaultExportPageSize is the number of audit records returned per page
	// when the caller does not specify a page size.
	defaultExportPageSize = 500

	// maxExportPageSize bounds the amount of records served in a single
	// export page.
	maxExportPageSize = 10000

	// defaultEnumerationPageSize is the page size used while walking the
	// datastore keyset pagination to build an export snapshot.
	defaultEnumerationPageSize = 1000

	// defaultSnapshotTTL bounds how long an export snapshot (and its page
	// token) is kept while a caller pages through the export.
	defaultSnapshotTTL = 10 * time.Minute

	// defaultMaxSnapshots bounds the number of concurrently retained export
	// snapshots per exporter.
	defaultMaxSnapshots = 64

	// maskedSecretValue replaces entry fields that may carry secret material
	// (such as the entry hint) in audit export output.
	maskedSecretValue = "[REDACTED]"
)

// AuditAuthorizeFunc filters the candidate entries of an export snapshot down
// to the ones the operator is allowed to export. It receives the candidate
// entry IDs and returns the set of allowed entry IDs. It is only invoked when
// an export snapshot is created (the first page request); subsequent pages
// are served from the already authorized snapshot.
type AuditAuthorizeFunc func(ctx context.Context, entryIDs []string) (map[string]struct{}, error)

// AuditExportRequest is the request to export registration entries for audit
// purposes. The export is strictly read-only: it never creates, updates or
// deletes registration entries.
type AuditExportRequest struct {
	// TrustDomain restricts the export to entries whose SPIFFE ID belongs to
	// the given trust domain. Required.
	TrustDomain spiffeid.TrustDomain

	// CreatedAfter filters entries by their creation time. When set, only
	// entries created at or after the given time are exported.
	CreatedAfter time.Time

	// CreatedBefore filters entries by their creation time. When set, only
	// entries created before the given time are exported.
	CreatedBefore time.Time

	// Operator is the identity performing the export. It is stamped on every
	// exported record and used to authorize snapshot page requests.
	Operator spiffeid.ID

	// PageSize is the maximum number of records returned per page. When zero
	// or negative, a default page size is used.
	PageSize int32

	// PageToken is the opaque token returned in a previous export response.
	// When empty, a new consistent snapshot is created.
	PageToken string

	// Authorize optionally filters the snapshot entries according to the
	// permissions of the operator.
	Authorize AuditAuthorizeFunc
}

// AuditEntryRecord is a single, redacted registration entry row in an audit
// export. It deliberately contains a subset of the registration entry data:
// fields that may carry secret material are never exported in clear text.
type AuditEntryRecord struct {
	// EntryID is the registration entry ID.
	EntryID string

	// SpiffeID is the SPIFFE ID of the entry.
	SpiffeID string

	// RevisionNumber is the entry revision at the time the export snapshot
	// was taken.
	RevisionNumber int64

	// Operator is the identity that requested the export.
	Operator string

	// SelectorSummary is a stable, comma separated summary of the entry
	// selectors in the form "type:value".
	SelectorSummary string

	// Revoked reports whether the entry was revoked (invalidated by its
	// expiry) at the time the export snapshot was taken.
	Revoked bool

	// CreatedAt is the entry creation time.
	CreatedAt time.Time

	// Hint is always redacted. It is set to MaskedSecretValue when the entry
	// has a hint, because hints may carry secret material. The raw hint value
	// is never exported.
	Hint string
}

// AuditExportResponse contains a page of audit records and, when more records
// are available, an opaque token to fetch the next page of the same
// consistent snapshot.
type AuditExportResponse struct {
	// Records are the audit records of the current page.
	Records []*AuditEntryRecord

	// NextPageToken is used in a following request to read the next page of
	// the same snapshot. It is empty when there are no more records.
	NextPageToken string

	// TrustDomain is the trust domain the snapshot was filtered on.
	TrustDomain string

	// Operator is the identity the snapshot was exported by.
	Operator string

	// SnapshotAt is the time at which the snapshot was taken. All pages of
	// the same export share this time.
	SnapshotAt time.Time
}

// AuditExporterConfig configures an AuditExporter.
type AuditExporterConfig struct {
	// DataStore is used read-only to enumerate registration entries.
	DataStore datastore.DataStore

	// Clock is used to compute revocation status and snapshot expiry.
	Clock clock.Clock

	// Log is used to report exporter errors. Optional.
	Log logrus.FieldLogger

	// EnumerationPageSize is the datastore page size used while building a
	// snapshot. Defaults to defaultEnumerationPageSize.
	EnumerationPageSize int32

	// SnapshotTTL bounds how long snapshot page tokens remain valid. Defaults
	// to defaultSnapshotTTL.
	SnapshotTTL time.Duration

	// MaxSnapshots bounds the number of retained snapshots. Defaults to
	// defaultMaxSnapshots.
	MaxSnapshots int
}

// AuditExporter exports redacted registration entry audit records using
// consistent pagination snapshots.
type AuditExporter struct {
	ds           datastore.DataStore
	clk          clock.Clock
	log          logrus.FieldLogger
	pageSize     int32
	snapshotTTL  time.Duration
	maxSnapshots int

	mu        sync.Mutex
	snapshots map[string]*auditSnapshot
}

// auditSnapshot is an immutable, consistent view of the records exported by a
// single export request. Pages are slices of the snapshot records, so
// concurrent entry updates and deletes cannot alter pages already served or
// pages yet to be served.
type auditSnapshot struct {
	token       string
	operator    string
	trustDomain string
	records     []*AuditEntryRecord
	createdAt   time.Time
	offset      int
}

// NewAuditExporter creates a new audit exporter.
func NewAuditExporter(c AuditExporterConfig) *AuditExporter {
	if c.Clock == nil {
		c.Clock = clock.New()
	}
	if c.EnumerationPageSize <= 0 {
		c.EnumerationPageSize = defaultEnumerationPageSize
	}
	if c.SnapshotTTL <= 0 {
		c.SnapshotTTL = defaultSnapshotTTL
	}
	if c.MaxSnapshots <= 0 {
		c.MaxSnapshots = defaultMaxSnapshots
	}

	return &AuditExporter{
		ds:           c.DataStore,
		clk:          c.Clock,
		log:          c.Log,
		pageSize:     c.EnumerationPageSize,
		snapshotTTL:  c.SnapshotTTL,
		maxSnapshots: c.MaxSnapshots,
		snapshots:    make(map[string]*auditSnapshot),
	}
}

// ExportRegistrationEntries exports a page of registration entry audit
// records matching the request. The first request (empty page token) creates a
// consistent snapshot; following requests page through that snapshot. The
// operation only reads registration entries and never modifies them.
func (x *AuditExporter) ExportRegistrationEntries(ctx context.Context, req *AuditExportRequest) (*AuditExportResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "missing export request")
	}
	if x.ds == nil {
		return nil, status.Error(codes.Internal, "audit exporter is not configured with a datastore")
	}
	if req.TrustDomain.IsZero() {
		return nil, status.Error(codes.InvalidArgument, "missing trust domain filter")
	}
	if !req.CreatedAfter.IsZero() && !req.CreatedBefore.IsZero() && req.CreatedBefore.Before(req.CreatedAfter) {
		return nil, status.Error(codes.InvalidArgument, "created_before cannot be before created_after")
	}
	if req.Operator.IsZero() {
		return nil, status.Error(codes.InvalidArgument, "missing operator")
	}

	pageSize := req.PageSize
	if pageSize <= 0 {
		pageSize = defaultExportPageSize
	}
	if pageSize > maxExportPageSize {
		pageSize = maxExportPageSize
	}

	if req.PageToken != "" {
		return x.serveSnapshotPage(req.PageToken, req.Operator.String(), pageSize)
	}

	snapshotAt := x.clk.Now()

	entries, err := x.enumerateEntries(ctx)
	if err != nil {
		return nil, err
	}

	entries = filterEntriesForExport(entries, req)

	if req.Authorize != nil {
		entryIDs := make([]string, 0, len(entries))
		for _, entry := range entries {
			entryIDs = append(entryIDs, entry.EntryId)
		}

		allowed, err := req.Authorize(ctx, entryIDs)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to authorize export entries: %v", err)
		}

		authorized := entries[:0]
		for _, entry := range entries {
			if _, ok := allowed[entry.EntryId]; ok {
				authorized = append(authorized, entry)
			}
		}
		entries = authorized
	}

	records := toAuditRecords(entries, req.Operator, snapshotAt)
	if len(records) == 0 {
		// Nothing to export: answer directly without retaining a snapshot.
		return &AuditExportResponse{
			TrustDomain: req.TrustDomain.Name(),
			Operator:    req.Operator.String(),
			SnapshotAt:  snapshotAt,
		}, nil
	}

	snapshot := &auditSnapshot{
		token:       newSnapshotToken(),
		operator:    req.Operator.String(),
		trustDomain: req.TrustDomain.Name(),
		records:     records,
		createdAt:   snapshotAt,
	}

	x.storeSnapshot(snapshot)

	return x.serveSnapshotPage(snapshot.token, req.Operator.String(), pageSize)
}

// serveSnapshotPage returns the next page of records of the snapshot
// identified by token. Snapshot pages belong to the operator that created the
// snapshot and cannot be read by another operator.
func (x *AuditExporter) serveSnapshotPage(token, operator string, pageSize int32) (*AuditExportResponse, error) {
	x.mu.Lock()
	defer x.mu.Unlock()

	x.pruneSnapshotsLocked(x.clk.Now())

	snapshot, ok := x.snapshots[token]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid or expired export page token")
	}
	if snapshot.operator != operator {
		// Keep the snapshot alive and return a permission error without
		// revealing whether the token exists.
		return nil, status.Error(codes.PermissionDenied, "export page token belongs to another operator")
	}

	if snapshot.offset >= len(snapshot.records) {
		// The caller is paging past the last page; the snapshot has already
		// been consumed.
		delete(x.snapshots, token)
		return nil, status.Error(codes.InvalidArgument, "invalid or expired export page token")
	}

	end := snapshot.offset + int(pageSize)
	if end >= len(snapshot.records) {
		end = len(snapshot.records)
	}

	resp := &AuditExportResponse{
		Records:     snapshot.records[snapshot.offset:end],
		TrustDomain: snapshot.trustDomain,
		Operator:    snapshot.operator,
		SnapshotAt:  snapshot.createdAt,
	}
	snapshot.offset = end
	if snapshot.offset < len(snapshot.records) {
		resp.NextPageToken = snapshot.token
	} else {
		// The snapshot is fully consumed and cannot be reused.
		delete(x.snapshots, token)
	}
	return resp, nil
}

// storeSnapshot registers a newly created snapshot, pruning expired snapshots
// and, when necessary, evicting the oldest snapshot.
func (x *AuditExporter) storeSnapshot(snapshot *auditSnapshot) {
	x.mu.Lock()
	defer x.mu.Unlock()

	now := x.clk.Now()
	x.pruneSnapshotsLocked(now)

	if len(x.snapshots) >= x.maxSnapshots {
		var oldestToken string
		var oldestTime time.Time
		for token, snap := range x.snapshots {
			if oldestToken == "" || snap.createdAt.Before(oldestTime) {
				oldestToken = token
				oldestTime = snap.createdAt
			}
		}
		delete(x.snapshots, oldestToken)
	}

	x.snapshots[snapshot.token] = snapshot
}

// pruneSnapshotsLocked removes snapshots whose TTL has elapsed. Callers must
// hold x.mu.
func (x *AuditExporter) pruneSnapshotsLocked(now time.Time) {
	for token, snapshot := range x.snapshots {
		if now.Sub(snapshot.createdAt) >= x.snapshotTTL {
			delete(x.snapshots, token)
		}
	}
}

// enumerateEntries walks the datastore keyset pagination and returns every
// registration entry. It only performs read-only datastore calls.
func (x *AuditExporter) enumerateEntries(ctx context.Context) ([]*common.RegistrationEntry, error) {
	var (
		entries []*common.RegistrationEntry
		token   string
	)

	for {
		resp, err := x.ds.ListRegistrationEntries(ctx, &datastore.ListRegistrationEntriesRequest{
			Pagination: &datastore.Pagination{
				PageSize: x.pageSize,
				Token:    token,
			},
		})
		if err != nil {
			x.logError("failed to list registration entries for audit export", err)
			return nil, status.Errorf(codes.Internal, "failed to list registration entries for audit export: %v", err)
		}

		entries = append(entries, resp.Entries...)

		if resp.Pagination == nil || resp.Pagination.Token == "" {
			return entries, nil
		}
		token = resp.Pagination.Token
	}
}

// filterEntriesForExport keeps entries belonging to the requested trust
// domain and within the requested creation time range.
func filterEntriesForExport(entries []*common.RegistrationEntry, req *AuditExportRequest) []*common.RegistrationEntry {
	filtered := entries[:0]
	for _, entry := range entries {
		spiffeID, err := spiffeid.FromString(entry.SpiffeId)
		if err != nil {
			// Entries are validated on creation, but skip defensively any
			// entry whose SPIFFE ID cannot be parsed instead of exporting an
			// unverifiable trust domain.
			continue
		}
		if spiffeID.TrustDomain().Name() != req.TrustDomain.Name() {
			continue
		}

		if !req.CreatedAfter.IsZero() || !req.CreatedBefore.IsZero() {
			createdAt := time.Unix(entry.CreatedAt, 0)
			if !req.CreatedAfter.IsZero() && createdAt.Before(req.CreatedAfter) {
				continue
			}
			if !req.CreatedBefore.IsZero() && !createdAt.Before(req.CreatedBefore) {
				continue
			}
		}

		filtered = append(filtered, entry)
	}
	return filtered
}

// toAuditRecords converts registration entries into redacted audit records.
// The records are built from the entry values as observed at snapshot time;
// the source entries are never modified.
func toAuditRecords(entries []*common.RegistrationEntry, operator spiffeid.ID, now time.Time) []*AuditEntryRecord {
	records := make([]*AuditEntryRecord, 0, len(entries))
	for _, entry := range entries {
		record := &AuditEntryRecord{
			EntryID:         entry.EntryId,
			SpiffeID:        entry.SpiffeId,
			RevisionNumber:  entry.RevisionNumber,
			Operator:        operator.String(),
			SelectorSummary: summarizeSelectors(entry.Selectors),
			Revoked:         isEntryRevoked(entry, now),
			CreatedAt:       time.Unix(entry.CreatedAt, 0).UTC(),
		}
		if entry.Hint != "" {
			record.Hint = maskedSecretValue
		}
		records = append(records, record)
	}
	return records
}

// isEntryRevoked reports whether an entry is invalidated by its expiry at the
// given time. Entries without an expiry cannot be revoked this way.
func isEntryRevoked(entry *common.RegistrationEntry, now time.Time) bool {
	return entry.EntryExpiry != 0 && !time.Unix(entry.EntryExpiry, 0).After(now)
}

// summarizeSelectors builds a stable, deduplicated summary of the entry
// selectors in the form "type:value", sorted lexicographically and joined by
// commas.
func summarizeSelectors(selectors []*common.Selector) string {
	if len(selectors) == 0 {
		return ""
	}

	seen := make(map[string]struct{}, len(selectors))
	parts := make([]string, 0, len(selectors))
	for _, selector := range selectors {
		part := selector.Type + ":" + selector.Value
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		parts = append(parts, part)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// newSnapshotToken generates an opaque, unguessable page token.
func newSnapshotToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should not fail; fall back to the current time so that
		// tokens remain unique.
		return time.Now().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}

func (x *AuditExporter) logError(msg string, err error) {
	if x.log != nil {
		x.log.WithError(err).Error(msg)
	}
}
