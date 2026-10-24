package registration

import (
	"context"
	"time"

	"github.com/andres-erbsen/clock"
	"github.com/sirupsen/logrus"
	"github.com/spiffe/spire/pkg/common/telemetry"
	telemetry_server "github.com/spiffe/spire/pkg/common/telemetry/server"
	"github.com/spiffe/spire/pkg/server/datastore"
)

const (
	_pruningCadence = 5 * time.Minute
)

// ManagerConfig is the config for the registration manager
type ManagerConfig struct {
	DataStore datastore.DataStore

	Log     logrus.FieldLogger
	Metrics telemetry.Metrics

	Clock clock.Clock
}

// Manager is the manager of registrations
type Manager struct {
	c        ManagerConfig
	log      logrus.FieldLogger
	metrics  telemetry.Metrics
	exporter *AuditExporter
}

// NewManager creates a new registration manager
func NewManager(c ManagerConfig) *Manager {
	if c.Clock == nil {
		c.Clock = clock.New()
	}

	return &Manager{
		c:       c,
		log:     c.Log.WithField(telemetry.RetryInterval, _pruningCadence),
		metrics: c.Metrics,
		exporter: NewAuditExporter(AuditExporterConfig{
			DataStore: c.DataStore,
			Clock:     c.Clock,
			Log:       c.Log,
		}),
	}
}

// AuditExporter returns the registration entry audit exporter backing the
// manager. The exporter keeps the consistent pagination snapshots used to
// serve audit exports.
func (m *Manager) AuditExporter() *AuditExporter {
	return m.exporter
}

// ExportRegistrationEntries exports a page of redacted registration entry
// audit records (revision, operator, selector summary and revocation status)
// filtered by trust domain and creation time range. The export only reads
// registration entries and never creates, updates or deletes them. Paging is
// backed by a consistent snapshot, so concurrent entry updates and deletes
// cannot change the records of an export in progress.
func (m *Manager) ExportRegistrationEntries(ctx context.Context, req *AuditExportRequest) (*AuditExportResponse, error) {
	return m.exporter.ExportRegistrationEntries(ctx, req)
}

// Run runs the registration manager
func (m *Manager) Run(ctx context.Context) error {
	return m.pruneEvery(ctx)
}

func (m *Manager) pruneEvery(ctx context.Context) error {
	ticker := m.c.Clock.Ticker(_pruningCadence)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Log an error on failure unless we're shutting down
			if err := m.prune(ctx); err != nil && ctx.Err() == nil {
				m.log.WithError(err).Error("Failed pruning registration entries")
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (m *Manager) prune(ctx context.Context) (err error) {
	counter := telemetry_server.StartRegistrationManagerPruneEntryCall(m.c.Metrics)
	defer counter.Done(&err)

	err = m.c.DataStore.PruneRegistrationEntries(ctx, m.c.Clock.Now())
	return err
}
