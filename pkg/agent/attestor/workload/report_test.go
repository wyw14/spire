package attestor

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/fakes/fakeagentcatalog"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestWorkloadAttestationReport(t *testing.T) {
	suite.Run(t, new(ReportTestSuite))
}

type ReportTestSuite struct {
	suite.Suite

	attestor *attestor
	catalog  *fakeagentcatalog.Catalog
}

func (s *ReportTestSuite) SetupTest() {
	log, _ := test.NewNullLogger()

	s.catalog = fakeagentcatalog.New()
	s.attestor = newAttestor(&Config{
		Catalog: s.catalog,
		Log:     log,
		Metrics: telemetry.Blackhole{},
	})
}

// staticAttestor is a minimal, concurrency-safe workload attestor source
// without the plugin machinery.
type staticAttestor struct {
	name      string
	selectors []*common.Selector
	err       error
}

func (a *staticAttestor) Name() string { return a.name }
func (a *staticAttestor) Type() string { return "WorkloadAttestor" }
func (a *staticAttestor) Attest(context.Context, int) ([]*common.Selector, error) {
	return a.selectors, a.err
}
func (a *staticAttestor) AttestReference(context.Context, *anypb.Any) ([]*common.Selector, error) {
	return a.selectors, a.err
}

// blockingAttestor blocks until the context is cancelled, signalling on
// started once the invocation is in flight.
type blockingAttestor struct {
	name    string
	started chan struct{}
	once    sync.Once
}

func newBlockingAttestor(name string) *blockingAttestor {
	return &blockingAttestor{
		name:    name,
		started: make(chan struct{}, 1),
	}
}

func (a *blockingAttestor) Name() string { return a.name }
func (a *blockingAttestor) Type() string { return "WorkloadAttestor" }
func (a *blockingAttestor) Attest(ctx context.Context, _ int) ([]*common.Selector, error) {
	a.once.Do(func() { a.started <- struct{}{} })
	<-ctx.Done()
	return nil, ctx.Err()
}
func (a *blockingAttestor) AttestReference(ctx context.Context, _ *anypb.Any) ([]*common.Selector, error) {
	return a.Attest(ctx, 0)
}

func sourceNames(results []SourceResult) []string {
	names := make([]string, 0, len(results))
	for _, r := range results {
		names = append(names, r.Name)
	}
	return names
}

func (s *ReportTestSuite) TestSucceededSourcesAreQueryable() {
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", selectors: selectors1},
		&staticAttestor{name: "fake2", selectors: selectors2},
	)

	selectors, report, err := s.attestor.AttestWithReport(ctx, 4)
	s.Require().NoError(err)
	s.Require().NotNil(report)

	// The report identifies the request and its generation.
	s.Equal(IngressPID, report.Ingress)
	s.Equal(4, report.PID)
	s.NotZero(report.Generation)
	s.False(report.StartedAt.IsZero())
	s.False(report.CompletedAt.Before(report.StartedAt))

	// Both sources succeeded, in catalog order; nothing failed or is pending.
	s.Equal([]string{"fake1", "fake2"}, sourceNames(report.Results()))
	s.Equal([]string{"fake1", "fake2"}, sourceNames(report.Succeeded()))
	s.Empty(report.Failed())
	s.Empty(report.Pending())
	s.Empty(report.Skipped())

	for _, result := range report.Succeeded() {
		s.Equal(StateSucceeded, result.State)
		s.Equal(StageInvoke, result.Stage)
		s.False(result.StartedAt.IsZero())
		s.False(result.EndedAt.Before(result.StartedAt))
		s.Nil(result.Err)
	}

	// Per-source selectors and the aggregated view are consistent.
	r1, ok := report.Result("fake1")
	s.Require().True(ok)
	s.Equal(selectors1, r1.Selectors)

	combined := report.Selectors()
	util.SortSelectors(combined)
	util.SortSelectors(selectors)
	expected := append(append([]*common.Selector{}, selectors1...), selectors2...)
	util.SortSelectors(expected)
	s.Equal(expected, combined)
	s.Equal(selectors, combined)

	s.Nil(report.FailedError())
}

func (s *ReportTestSuite) TestPartialFailureKeepsFailureQueryable() {
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", err: errors.New("boom")},
		&staticAttestor{name: "fake2", selectors: selectors2},
	)

	selectors, report, err := s.attestor.AttestWithReport(ctx, 3)
	s.Require().NoError(err)
	s.Require().NotNil(report)

	// Partial failures do not fail the request; the successful source still
	// contributes its selectors.
	s.Equal(selectors2, selectors)
	s.Equal([]string{"fake2"}, sourceNames(report.Succeeded()))
	s.Equal(selectors2, report.Succeeded()[0].Selectors)
	s.Empty(report.Pending())

	failed := report.Failed()
	s.Require().Len(failed, 1)
	s.Equal("fake1", failed[0].Name)
	s.Equal(StateFailed, failed[0].State)
	s.Equal(StageInvoke, failed[0].Stage)

	// The error locates the ingress, source and stage.
	var sourceErr *SourceError
	s.Require().ErrorAs(failed[0].Err, &sourceErr)
	s.Equal(IngressPID, sourceErr.Ingress)
	s.Equal("fake1", sourceErr.Source)
	s.Equal(StageInvoke, sourceErr.Stage)
	s.Equal(`workload attestor "fake1" failed: boom`, sourceErr.Error())
	s.EqualError(failed[0].Err, `workload attestor "fake1" failed: boom`)

	// FailedError exposes the same error.
	s.EqualError(report.FailedError(), `workload attestor "fake1" failed: boom`)
}

func (s *ReportTestSuite) TestAllFailuresJoinLocatedErrors() {
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", err: errors.New("boom1")},
		&staticAttestor{name: "fake2", err: errors.New("boom2")},
	)

	_, report, err := s.attestor.AttestWithReport(ctx, 5)
	s.Require().Error(err)
	s.Require().NotNil(report)
	s.ErrorContains(err, `workload attestor "fake1" failed: boom1`)
	s.ErrorContains(err, `workload attestor "fake2" failed: boom2`)

	// The joined, returned error can be located to a source via errors.As.
	var sourceErr *SourceError
	s.Require().ErrorAs(err, &sourceErr)
	s.Equal(IngressPID, sourceErr.Ingress)
	s.Equal(StageInvoke, sourceErr.Stage)

	// Every failed source is independently queryable with its location.
	failed := report.Failed()
	s.Require().Len(failed, 2)
	for i, result := range failed {
		s.Equal(StateFailed, result.State)
		var se *SourceError
		s.Require().ErrorAs(result.Err, &se, "result %d", i)
		s.Equal(result.Name, se.Source)
		s.Equal(IngressPID, se.Ingress)
		s.Equal(StageInvoke, se.Stage)
	}
	s.Empty(report.Succeeded())
	s.Empty(report.Pending())
	s.Empty(report.Skipped())
}

func (s *ReportTestSuite) TestReferenceIngressRecordsSkippedSources() {
	reference := &anypb.Any{TypeUrl: "type.googleapis.com/example.Reference"}

	s.catalog.SetWorkloadAttestors(
		&referenceWorkloadAttestor{name: "k8s", selectors: selectors1},
		&referenceWorkloadAttestor{name: "unix", err: status.Error(codes.Unimplemented, "AttestReference not implemented")},
	)

	selectors, report, err := s.attestor.AttestReferenceWithReport(ctx, reference)
	s.Require().NoError(err)
	s.Require().NotNil(report)
	s.Equal(IngressReference, report.Ingress)
	s.Equal("type.googleapis.com/example.Reference", report.ReferenceType)
	s.Equal(selectors1, selectors)

	s.Equal([]string{"k8s"}, sourceNames(report.Succeeded()))
	skipped := report.Skipped()
	s.Require().Len(skipped, 1)
	s.Equal("unix", skipped[0].Name)
	s.Equal(StateSkipped, skipped[0].State)
	s.Equal(StageInvoke, skipped[0].Stage)
	s.Empty(report.Failed())
	s.Empty(report.Pending())

	// When every source skips the reference, the legacy Unimplemented error is
	// returned together with a still-queryable report.
	s.catalog.SetWorkloadAttestors(
		&referenceWorkloadAttestor{name: "unix", err: status.Error(codes.Unimplemented, "AttestReference not implemented")},
		&referenceWorkloadAttestor{name: "docker", err: status.Error(codes.Unimplemented, "AttestReference not implemented")},
	)
	_, report, err = s.attestor.AttestReferenceWithReport(ctx, reference)
	s.Require().Error(err)
	s.Equal(codes.Unimplemented, status.Code(err))
	s.Require().NotNil(report)
	s.Len(report.Skipped(), 2)
	s.Empty(report.Succeeded())
}

func (s *ReportTestSuite) TestPendingSourcesAreQueryableOnCancellation() {
	blocker := newBlockingAttestor("blocker")
	selectorSeen := make(chan struct{}, 1)
	s.attestor.c.selectorHook = func([]*common.Selector) {
		selectorSeen <- struct{}{}
	}
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fast", selectors: selectors1},
		blocker,
	)

	reqCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var (
		gotSelectors []*common.Selector
		gotReport    *Report
		gotErr       error
	)
	go func() {
		gotSelectors, gotReport, gotErr = s.attestor.AttestWithReport(reqCtx, 4)
		close(done)
	}()

	// Wait until the blocking source is in flight and the fast source has been
	// collected, then cancel the request.
	select {
	case <-blocker.started:
	case <-time.After(5 * time.Second):
		s.FailNow("timed out waiting for blocker to start")
	}
	select {
	case <-selectorSeen:
	case <-time.After(5 * time.Second):
		s.FailNow("timed out waiting for fast source selectors")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		s.FailNow("attestation did not return after cancellation")
	}

	s.Nil(gotSelectors)
	s.ErrorIs(gotErr, context.Canceled)
	s.Require().NotNil(gotReport)

	s.Equal([]string{"fast"}, sourceNames(gotReport.Succeeded()))
	pending := gotReport.Pending()
	s.Require().Len(pending, 1)
	s.Equal("blocker", pending[0].Name)
	s.Equal(StatePending, pending[0].State)
	s.Equal(StageCollect, pending[0].Stage)
	s.True(pending[0].EndedAt.IsZero())
	s.Empty(gotReport.Failed())
	s.Empty(gotReport.Skipped())
}

func (s *ReportTestSuite) TestGenerationsAreUniqueAcrossConcurrentRequests() {
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", selectors: selectors1},
		&staticAttestor{name: "fake2", selectors: selectors2},
	)

	const concurrency = 50
	type concurrentResult struct {
		selectors []*common.Selector
		report    *Report
		err       error
	}
	var wg sync.WaitGroup
	results := make(chan concurrentResult, concurrency)
	start := make(chan struct{})
	for range concurrency {
		wg.Go(func() {
			<-start
			selectors, report, err := s.attestor.AttestWithReport(ctx, 4)
			results <- concurrentResult{selectors: selectors, report: report, err: err}
		})
	}
	close(start)

	// Wait for completion, then assert on the test goroutine (FailNow must not
	// be called from a spawned goroutine).
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		s.FailNow("concurrent attestations did not finish")
	}
	close(results)

	seen := make(map[uint64]struct{}, concurrency)
	for result := range results {
		s.Require().NoError(result.err)
		s.Require().Len(result.selectors, 2)
		// Every concurrent request has its own independent report.
		s.Len(result.report.Results(), 2)
		s.Len(result.report.Succeeded(), 2)
		s.Empty(result.report.Failed())
		s.Empty(result.report.Pending())
		_, dup := seen[result.report.Generation]
		s.False(dup, "duplicate generation %d across concurrent requests", result.report.Generation)
		seen[result.report.Generation] = struct{}{}
	}
	s.Len(seen, concurrency)

	// Generations keep increasing across ingresses too.
	pidGen := s.attestor.generation.Load()
	_, refReport, err := s.attestor.AttestReferenceWithReport(ctx, &anypb.Any{
		TypeUrl: "type.googleapis.com/example.Reference",
	})
	s.Require().NoError(err)
	s.Greater(refReport.Generation, pidGen)
}

func (s *ReportTestSuite) TestFailureDoesNotPolluteSubsequentRequest() {
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", err: errors.New("boom1")},
		&staticAttestor{name: "fake2", err: errors.New("boom2")},
	)

	_, failedReport, err := s.attestor.AttestWithReport(ctx, 5)
	s.Require().Error(err)
	s.Len(failedReport.Failed(), 2)

	// A subsequent request with healthy sources starts from a clean state:
	// it inherits no failures or pending sources from the previous request.
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", selectors: selectors1},
		&staticAttestor{name: "fake2", selectors: selectors2},
	)
	selectors, okReport, err := s.attestor.AttestWithReport(ctx, 4)
	s.Require().NoError(err)
	s.Require().NotNil(okReport)
	s.Greater(okReport.Generation, failedReport.Generation)
	s.Len(okReport.Succeeded(), 2)
	s.Empty(okReport.Failed())
	s.Empty(okReport.Pending())
	s.Empty(okReport.Skipped())
	s.Nil(okReport.FailedError())
	s.Len(selectors, len(selectors1)+len(selectors2))
}

func (s *ReportTestSuite) TestLatestReportRetainedOnlyWhenFlagEnabled() {
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", selectors: selectors1},
		&staticAttestor{name: "fake2", selectors: selectors2},
	)

	// Default (flag disabled): reports are returned to explicit callers but
	// nothing is retained and the legacy path is unaffected.
	_, report, err := s.attestor.AttestWithReport(ctx, 4)
	s.Require().NoError(err)
	s.Require().NotNil(report)
	s.Nil(s.attestor.LatestReport())

	s.Require().NoError(fflag.Load(fflag.RawConfig{string(fflag.FlagWorkloadAttestationProvenance)}))
	s.T().Cleanup(func() { _ = fflag.Unload() })

	// Flag enabled: the latest report is retained and queryable.
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", err: errors.New("boom")},
		&staticAttestor{name: "fake2", selectors: selectors2},
	)
	_, partial, err := s.attestor.AttestWithReport(ctx, 3)
	s.Require().NoError(err)
	s.Same(partial, s.attestor.LatestReport())
	s.Len(s.attestor.LatestReport().Failed(), 1)

	// A newer request replaces the retained snapshot; the old report remains
	// immutable and is not mutated by the new request.
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", selectors: selectors1},
		&staticAttestor{name: "fake2", selectors: selectors2},
	)
	_, success, err := s.attestor.AttestWithReport(ctx, 4)
	s.Require().NoError(err)
	s.Same(success, s.attestor.LatestReport())
	s.Len(s.attestor.LatestReport().Succeeded(), 2)
	s.Len(partial.Failed(), 1, "older report must remain unchanged")
	s.Len(partial.Succeeded(), 1)
}

func (s *ReportTestSuite) TestLegacyMethodsAndDefaultsStayCompatible() {
	s.catalog.SetWorkloadAttestors(
		&staticAttestor{name: "fake1", selectors: selectors1},
		&staticAttestor{name: "fake2", err: errors.New("boom")},
	)

	// Legacy method keeps returning selectors and error only.
	selectors, err := s.attestor.Attest(ctx, 3)
	s.Require().NoError(err)
	s.Equal(selectors1, selectors)

	// nil selectorHook and nil Clock are replaced with safe defaults.
	fresh := newAttestor(&Config{
		Catalog: s.catalog,
		Log:     s.attestor.c.Log,
		Metrics: telemetry.Blackhole{},
	})
	s.NotNil(fresh.c.Clock)
	s.NotNil(fresh.c.selectorHook)
	s.NotPanics(func() { fresh.c.selectorHook(nil) })

	// Querying a nil report is safe.
	var nilReport *Report
	s.Nil(nilReport.Results())
	s.Nil(nilReport.Succeeded())
	s.Nil(nilReport.Failed())
	s.Nil(nilReport.Pending())
	s.Nil(nilReport.Skipped())
	s.Nil(nilReport.Selectors())
	s.Nil(nilReport.FailedError())
	_, ok := nilReport.Result("anything")
	s.False(ok)

	// The concrete attestor satisfies both interfaces.
	var _ ReportingAttestor = fresh
	var _ Attestor = fresh
}
