package attestor

import (
	"errors"
	"time"

	"github.com/spiffe/spire/proto/spire/common"
)

// Ingress identifies the entry point through which an attestation request
// entered the agent.
type Ingress string

const (
	// IngressPID marks requests attested from a peer process PID over the
	// Workload API / SDS.
	IngressPID Ingress = "pid"
	// IngressReference marks requests attested from an opaque reference (for
	// example, delegated through the Broker API).
	IngressReference Ingress = "reference"
)

// Stage identifies the processing stage a source had reached when its result
// was recorded.
type Stage string

const (
	// StageDispatch means the request was dispatched to the source plugin but
	// no outcome had been produced when the request ended.
	StageDispatch Stage = "dispatch"
	// StageInvoke means the source plugin produced an outcome (either
	// selectors or an error) that was collected.
	StageInvoke Stage = "invoke"
	// StageCollect means the request ended (for example, because its context
	// was cancelled) before the source outcome could be collected; the source
	// is still pending.
	StageCollect Stage = "collect"
)

// State is the outcome recorded for a single attestation source.
type State string

const (
	// StatePending means the source had not produced a collected outcome when
	// the request ended.
	StatePending State = "pending"
	// StateSucceeded means the source returned selectors.
	StateSucceeded State = "succeeded"
	// StateFailed means the source returned an error.
	StateFailed State = "failed"
	// StateSkipped means the source does not handle the request ingress (for
	// example, a plugin that does not implement reference attestation).
	StateSkipped State = "skipped"
)

// SourceError associates an attestation failure with the ingress it came from,
// the source (workload attestor plugin) that produced it, and the stage at
// which it occurred. Its Error message is identical to the underlying failure,
// so wrapping it does not alter any operator-visible error text; callers can
// use errors.As to locate the ingress, source and stage programmatically.
type SourceError struct {
	Ingress Ingress
	Source  string
	Stage   Stage
	Err     error
}

func (e *SourceError) Error() string {
	return e.Err.Error()
}

func (e *SourceError) Unwrap() error {
	return e.Err
}

// SourceResult is the recorded outcome of a single attestation source.
type SourceResult struct {
	// Name is the workload attestor plugin name, i.e. the source.
	Name string
	// State is the recorded outcome.
	State State
	// Stage is the processing stage at which the outcome was recorded.
	Stage Stage
	// Selectors are the selectors returned by the source. Only populated when
	// State is StateSucceeded.
	Selectors []*common.Selector
	// Err is the failure returned by the source. Only populated when State is
	// StateFailed. It wraps a *SourceError so the ingress, source and stage
	// can be extracted with errors.As.
	Err error
	// StartedAt is when the request was dispatched to the source.
	StartedAt time.Time
	// EndedAt is when the outcome was collected. Zero while pending.
	EndedAt time.Time
}

// Report is an immutable, per-request record of an attestation attempt. A new
// report is created for every request, so outcomes recorded for one request
// can never be observed by, or otherwise pollute, another request.
type Report struct {
	// Generation uniquely and monotonically identifies this attestation
	// request within the agent. Concurrent requests receive distinct
	// generations.
	Generation uint64
	// Ingress is the entry point through which the request entered.
	Ingress Ingress
	// PID is the attested process ID when Ingress is IngressPID.
	PID int
	// ReferenceType is the type URL of the attested reference when Ingress is
	// IngressReference.
	ReferenceType string
	// StartedAt is when the attestation request started.
	StartedAt time.Time
	// CompletedAt is when the attestation request completed. Sources still
	// pending at this time remain in StatePending.
	CompletedAt time.Time

	// results holds one entry per configured source, in catalog order.
	results []SourceResult
}

// Results returns the per-source results in catalog (deterministic) order.
func (r *Report) Results() []SourceResult {
	if r == nil {
		return nil
	}
	out := make([]SourceResult, len(r.results))
	copy(out, r.results)
	return out
}

// ByState returns the sources currently in the given state, in catalog order.
func (r *Report) ByState(state State) []SourceResult {
	if r == nil {
		return nil
	}
	var out []SourceResult
	for _, result := range r.results {
		if result.State == state {
			out = append(out, result)
		}
	}
	return out
}

// Succeeded returns the sources that returned selectors.
func (r *Report) Succeeded() []SourceResult {
	return r.ByState(StateSucceeded)
}

// Failed returns the sources that returned an error.
func (r *Report) Failed() []SourceResult {
	return r.ByState(StateFailed)
}

// Pending returns the sources that had not produced a collected outcome when
// the request completed.
func (r *Report) Pending() []SourceResult {
	return r.ByState(StatePending)
}

// Skipped returns the sources that do not handle the request ingress.
func (r *Report) Skipped() []SourceResult {
	return r.ByState(StateSkipped)
}

// Result returns the recorded result for the named source.
func (r *Report) Result(source string) (SourceResult, bool) {
	if r == nil {
		return SourceResult{}, false
	}
	for _, result := range r.results {
		if result.Name == source {
			return result, true
		}
	}
	return SourceResult{}, false
}

// Selectors returns all selectors produced by succeeded sources, in catalog
// order. It returns nil when no source produced selectors.
func (r *Report) Selectors() []*common.Selector {
	if r == nil {
		return nil
	}
	var selectors []*common.Selector
	for _, result := range r.results {
		if result.State == StateSucceeded {
			selectors = append(selectors, result.Selectors...)
		}
	}
	return selectors
}

// FailedError joins the errors of all failed sources. It returns nil when no
// source failed. Each joined error wraps a *SourceError.
func (r *Report) FailedError() error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, result := range r.results {
		if result.State == StateFailed {
			errs = append(errs, result.Err)
		}
	}
	return errors.Join(errs...)
}
