package attestor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/agent/catalog"
	"github.com/spiffe/spire/pkg/agent/plugin/workloadattestor"
	"github.com/spiffe/spire/pkg/common/fflag"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_workload "github.com/spiffe/spire/pkg/common/telemetry/agent/workloadapi"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

var errReferenceUnsupported = errors.New("workload reference type unsupported by attestor")

type attestor struct {
	c *Config

	// generation is incremented once per attestation request (regardless of
	// ingress) so concurrent requests can be correlated with their report.
	generation atomic.Uint64

	// latest holds the most recent completed report. It is only populated when
	// the workload-attestation-provenance feature flag is enabled; the stored
	// report is immutable and observational, so it cannot affect subsequent
	// requests.
	latest atomic.Pointer[Report]
}

type Attestor interface {
	Attest(ctx context.Context, pid int) ([]*common.Selector, error)
	AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error)
}

// ReportingAttestor is the opt-in extension of Attestor. In addition to the
// legacy methods, it exposes the provenance report of each attestation
// request, describing per-source (workload attestor plugin) succeeded,
// failed, pending and skipped outcomes, tagged with the request ingress and
// processing stage.
type ReportingAttestor interface {
	Attestor

	// AttestWithReport behaves like Attest and additionally returns the
	// per-request provenance report.
	AttestWithReport(ctx context.Context, pid int) ([]*common.Selector, *Report, error)

	// AttestReferenceWithReport behaves like AttestReference and additionally
	// returns the per-request provenance report.
	AttestReferenceWithReport(ctx context.Context, reference *anypb.Any) ([]*common.Selector, *Report, error)

	// LatestReport returns the most recent completed attestation report. It
	// returns nil unless the workload-attestation-provenance feature flag is
	// enabled.
	LatestReport() *Report
}

var (
	_ Attestor          = (*attestor)(nil)
	_ ReportingAttestor = (*attestor)(nil)
)

func New(config *Config) Attestor {
	return newAttestor(config)
}

func newAttestor(config *Config) *attestor {
	if config.selectorHook == nil {
		config.selectorHook = func([]*common.Selector) {}
	}
	if config.Clock == nil {
		config.Clock = clock.New()
	}

	return &attestor{c: config}
}

type Config struct {
	Catalog catalog.Catalog
	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	// Clock is used to timestamp attestation reports. Defaults to the system
	// clock when unset.
	Clock clock.Clock

	// Test hook called when selectors are obtained from a workload attestor plugin
	selectorHook func([]*common.Selector)
}

// Attest invokes all workload attestor plugins against the provided PID. If some
// attestors fail, the errors are logged and selectors from the failing plugins
// are discarded. If all attestors fail, the combined error is returned.
func (wla *attestor) Attest(ctx context.Context, pid int) ([]*common.Selector, error) {
	selectors, _, err := wla.AttestWithReport(ctx, pid)
	if err != nil {
		return nil, err
	}

	// The agent health check currently exercises the Workload API. Since this
	// can happen with some frequency, it has a tendency to fill up logs with
	// hard-to-filter details if we're not careful (e.g. issue #1537). Only log
	// if it is not the agent itself.
	if pid != os.Getpid() {
		wla.c.Log.WithField(telemetry.PID, pid).
			WithField(telemetry.Selectors, selectors).
			Debug("PID attested to have selectors")
	}

	return selectors, nil
}

// AttestWithReport behaves like Attest and additionally returns the provenance
// report describing the per-source outcomes.
func (wla *attestor) AttestWithReport(ctx context.Context, pid int) ([]*common.Selector, *Report, error) {
	log := wla.c.Log.WithField(telemetry.PID, pid)

	return wla.attest(ctx, IngressPID, pid, "", func(a workloadattestor.WorkloadAttestor) ([]*common.Selector, error) {
		var err error
		counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
		defer counter.Done(&err)

		selectors, err := a.Attest(ctx, pid)
		if err != nil {
			log.WithError(err).Errorf("workload attestor %q failed", a.Name())
			return nil, fmt.Errorf("workload attestor %q failed: %w", a.Name(), err)
		}
		return selectors, nil
	}, nil, nil)
}

func (wla *attestor) AttestReference(ctx context.Context, reference *anypb.Any) ([]*common.Selector, error) {
	selectors, _, err := wla.AttestReferenceWithReport(ctx, reference)
	if err != nil {
		return nil, err
	}
	wla.c.Log.WithField(telemetry.Selectors, selectors).Debug("Reference attested to have selectors")
	return selectors, nil
}

func (wla *attestor) AttestReferenceWithReport(ctx context.Context, reference *anypb.Any) ([]*common.Selector, *Report, error) {
	log := wla.c.Log.WithField(telemetry.ReferenceType, reference.GetTypeUrl())

	return wla.attest(ctx, IngressReference, 0, reference.GetTypeUrl(), func(a workloadattestor.WorkloadAttestor) ([]*common.Selector, error) {
		var err error
		counter := telemetry_workload.StartAttestorCall(wla.c.Metrics, a.Name())
		defer counter.Done(&err)

		selectors, err := a.AttestReference(ctx, reference)
		if err != nil {
			if status.Code(err) == codes.Unimplemented {
				log.WithError(err).Debugf("workload attestor %q does not support reference attestation", a.Name())
				return nil, errReferenceUnsupported
			}
			log.WithError(err).Errorf("workload attestor %q failed", a.Name())
			return nil, fmt.Errorf("workload attestor %q failed: %w", a.Name(), err)
		}
		return selectors, nil
	}, errReferenceUnsupported, status.Error(codes.Unimplemented, "no workload attestor handled reference"))
}

// LatestReport returns the most recent completed attestation report. It returns
// nil unless the workload-attestation-provenance feature flag is enabled.
func (wla *attestor) LatestReport() *Report {
	return wla.latest.Load()
}

// attest fans the request out to every workload attestor source and records a
// provenance report. The legacy contract is preserved exactly: on success the
// collected selectors are returned; partial failures are logged and discarded;
// if every source fails the joined error is returned; sources that do not
// handle the ingress are skipped; context cancellation aborts collection.
func (wla *attestor) attest(
	ctx context.Context,
	ingress Ingress,
	pid int,
	referenceType string,
	attestFunc func(attestor workloadattestor.WorkloadAttestor) ([]*common.Selector, error),
	skippableErr error,
	allSkippedErr error,
) (selectors []*common.Selector, report *Report, retErr error) {
	counter := telemetry_workload.StartAttestationCall(wla.c.Metrics)
	defer counter.Done(&retErr)

	plugins := wla.c.Catalog.GetWorkloadAttestors()

	startedAt := wla.c.Clock.Now()
	report = &Report{
		Generation:    wla.generation.Add(1),
		Ingress:       ingress,
		PID:           pid,
		ReferenceType: referenceType,
		StartedAt:     startedAt,
		results:       make([]SourceResult, len(plugins)),
	}
	for i, p := range plugins {
		// Every source starts pending at the dispatch stage and transitions to
		// succeeded, failed or skipped when its outcome is collected.
		report.results[i] = SourceResult{
			Name:      p.Name(),
			State:     StatePending,
			Stage:     StageDispatch,
			StartedAt: startedAt,
		}
	}

	type outcome struct {
		index     int
		selectors []*common.Selector
		err       error
		endedAt   time.Time
	}
	// Buffered so plugin goroutines never block sending if the outer loop
	// returns early (e.g., on ctx cancellation). Combined with the deferred
	// wg.Wait() below, this guarantees plugin-level logs are flushed before
	// we return to the caller.
	oChan := make(chan outcome, len(plugins))

	var wg sync.WaitGroup
	for i, p := range plugins {
		wg.Go(func() {
			selectors, err := attestFunc(p)
			oChan <- outcome{
				index:     i,
				selectors: selectors,
				err:       err,
				endedAt:   wla.c.Clock.Now(),
			}
		})
	}
	defer wg.Wait()

	// Collect the results
	selectors = []*common.Selector{}
	successes := 0
	skipped := 0
	var errs []error

	finalize := func() {
		now := wla.c.Clock.Now()
		report.CompletedAt = now
		for i := range report.results {
			// Sources whose outcome was never collected remain pending; mark
			// the stage at which the request left them.
			if report.results[i].State == StatePending {
				report.results[i].Stage = StageCollect
			}
		}
		if fflag.IsSet(fflag.FlagWorkloadAttestationProvenance) {
			wla.latest.Store(report)
			wla.c.Log.WithFields(logrus.Fields{
				telemetry.Generation: report.Generation,
				telemetry.Ingress:    string(report.Ingress),
				telemetry.Succeeded:  len(report.Succeeded()),
				telemetry.Failed:     len(report.Failed()),
				telemetry.Pending:    len(report.Pending()),
				telemetry.Skipped:    len(report.Skipped()),
			}).Debug("Attestation source report")
		}
	}

	for range plugins {
		select {
		case o := <-oChan:
			started := report.results[o.index].StartedAt
			switch {
			case o.err == nil:
				successes++
				selectors = append(selectors, o.selectors...)
				report.results[o.index] = SourceResult{
					Name:      plugins[o.index].Name(),
					State:     StateSucceeded,
					Stage:     StageInvoke,
					Selectors: o.selectors,
					StartedAt: started,
					EndedAt:   o.endedAt,
				}
				wla.c.selectorHook(selectors)
			case ctx.Err() != nil:
				wla.c.Log.WithError(ctx.Err()).Error("Timed out collecting selectors")
				finalize()
				return nil, report, ctx.Err()
			case skippableErr != nil && errors.Is(o.err, skippableErr):
				skipped++
				report.results[o.index] = SourceResult{
					Name:      plugins[o.index].Name(),
					State:     StateSkipped,
					Stage:     StageInvoke,
					StartedAt: started,
					EndedAt:   o.endedAt,
				}
			default:
				sourceErr := &SourceError{
					Ingress: ingress,
					Source:  plugins[o.index].Name(),
					Stage:   StageInvoke,
					Err:     o.err,
				}
				report.results[o.index] = SourceResult{
					Name:      plugins[o.index].Name(),
					State:     StateFailed,
					Stage:     StageInvoke,
					Err:       sourceErr,
					StartedAt: started,
					EndedAt:   o.endedAt,
				}
				errs = append(errs, sourceErr)
			}
		case <-ctx.Done():
			wla.c.Log.WithError(ctx.Err()).Error("Timed out collecting selectors")
			finalize()
			return nil, report, ctx.Err()
		}
	}

	finalize()

	if len(plugins) > 0 && successes == 0 {
		if len(errs) > 0 {
			return nil, report, errors.Join(errs...)
		}
		if skipped > 0 && allSkippedErr != nil {
			return nil, report, allSkippedErr
		}
	}

	if len(errs) > 0 {
		wla.c.Log.WithError(errors.Join(errs...)).Error("Failed to collect all selectors")
	}

	telemetry_workload.AddDiscoveredSelectorsSample(wla.c.Metrics, float32(len(selectors)))
	return selectors, report, nil
}
