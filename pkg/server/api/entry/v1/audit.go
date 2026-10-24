package entry

import (
	"context"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	commonapi "github.com/spiffe/spire/pkg/common/api"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/registration"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ExportAuditEntries exports a page of redacted registration entry audit
// records (revision, operator, selector summary and revocation status) for
// the server trust domain, optionally restricted by entry creation time
// range. Paging is backed by a consistent snapshot: entries updated or
// deleted while the export is in progress do not alter the exported records.
//
// The caller identity is stamped as the record operator and used to filter
// the snapshot down to entries the caller is authorized to see. The export is
// read-only and never modifies registration entries; fields that may carry
// secret material (such as the entry hint) are always redacted.
func (s *Service) ExportAuditEntries(ctx context.Context, req *registration.AuditExportRequest) (*registration.AuditExportResponse, error) {
	log := rpccontext.Logger(ctx)

	if req == nil {
		return nil, commonapi.MakeErr(log, codes.InvalidArgument, "missing request", nil)
	}

	operator, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, commonapi.MakeErr(log, codes.Internal, "caller ID missing from request context", nil)
	}

	// Copy the request so that the caller's value is never mutated. The
	// server trust domain and the caller identity are authoritative and
	// cannot be overridden by the caller.
	exportReq := *req
	exportReq.TrustDomain = s.td
	exportReq.Operator = operator
	exportReq.Authorize = authorizeAuditExport(s.ef, operator)

	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		telemetry.TrustDomain: s.td.Name(),
	})

	resp, err := s.auditExporter.ExportRegistrationEntries(ctx, &exportReq)
	if err != nil {
		return nil, commonapi.MakeErr(log, status.Code(err), "failed to export audit entries", err)
	}

	rpccontext.AuditRPC(ctx)

	return resp, nil
}

// authorizeAuditExport returns the snapshot authorization hook: it resolves
// which of the candidate entry IDs the operator is allowed to export using
// the service's authorized entry fetcher.
func authorizeAuditExport(fetcher api.AuthorizedEntryFetcher, operator spiffeid.ID) registration.AuditAuthorizeFunc {
	return func(ctx context.Context, entryIDs []string) (map[string]struct{}, error) {
		candidateIDs := make(map[string]struct{}, len(entryIDs))
		for _, entryID := range entryIDs {
			candidateIDs[entryID] = struct{}{}
		}

		authorized, err := fetcher.LookupAuthorizedEntries(ctx, operator, candidateIDs)
		if err != nil {
			return nil, err
		}

		allowed := make(map[string]struct{}, len(authorized))
		for entryID := range authorized {
			allowed[entryID] = struct{}{}
		}
		return allowed, nil
	}
}
