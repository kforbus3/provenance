package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// Persistence for the imaging control plane (docs/imaging.md).
//
// Flipside kept this in JSON files because it had no database. Here there is
// one, so machine state, rollouts and the provisioning record live in it and
// inherit row-level security, backups and the audit trail without any of it
// being written twice.

const machineCols = `id, host_id, hostname, address, slot, version, image, arch,
	agent_version, boot_id, health, update_state, update_error, update_rollout,
	reported_by, report_source, label, held, first_seen, last_seen, imaged_at, booted_at`

func scanMachine(row pgx.Row) (*models.ImagingMachine, error) {
	var m models.ImagingMachine
	err := row.Scan(&m.ID, &m.HostID, &m.Hostname, &m.Address, &m.Slot, &m.Version,
		&m.Image, &m.Arch, &m.AgentVersion, &m.BootID, &m.Health,
		&m.UpdateState, &m.UpdateError, &m.UpdateRollout,
		&m.ReportedBy, &m.ReportSource, &m.Label, &m.Held,
		&m.FirstSeen, &m.LastSeen, &m.ImagedAt, &m.BootedAt)
	if err != nil {
		return nil, err
	}
	return &m, nil
}

// ReportMachine records what a machine said about itself, or what something
// said about it having looked.
//
// Upsert rather than insert-or-update in two statements: a machine's first
// heartbeat and its ten-thousandth are the same call, and a fleet checking in
// concurrently must not race two of them into a duplicate-key error.
//
// Only non-empty fields are written. A report that omits a field is not
// asserting the field is empty -- the progress report a machine sends
// mid-install carries a state and no version, and treating that as "this
// machine now has no version" would lose the fleet's inventory every time
// somebody ran an update.
func (s *Store) ReportMachine(ctx context.Context, m *models.ImagingMachine) (*models.ImagingMachine, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO imaging_machines (id, hostname, address, slot, version,
			image, arch, agent_version, boot_id, health, update_state, update_error,
			update_rollout, reported_by, report_source, imaged_at, booted_at, last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17, now())
		ON CONFLICT (id) DO UPDATE SET
			hostname      = COALESCE(NULLIF(EXCLUDED.hostname, ''),      imaging_machines.hostname),
			address       = COALESCE(NULLIF(EXCLUDED.address, ''),       imaging_machines.address),
			slot          = COALESCE(NULLIF(EXCLUDED.slot, ''),          imaging_machines.slot),
			version       = COALESCE(NULLIF(EXCLUDED.version, ''),       imaging_machines.version),
			image         = COALESCE(NULLIF(EXCLUDED.image, ''),         imaging_machines.image),
			arch          = COALESCE(NULLIF(EXCLUDED.arch, ''),          imaging_machines.arch),
			agent_version = COALESCE(NULLIF(EXCLUDED.agent_version, ''), imaging_machines.agent_version),
			boot_id       = COALESCE(NULLIF(EXCLUDED.boot_id, ''),       imaging_machines.boot_id),
			health        = COALESCE(NULLIF(EXCLUDED.health, ''),        imaging_machines.health),
			-- An agent's empty update_state is written, because "idle" is a real
			-- thing for a machine to say and it is how one reports that it has
			-- finished. Anything else's empty update_state is NOT: an observation
			-- read off a host, or a report from the imager, means "I have nothing
			-- to say about this", and blanking a machine's state because the
			-- speaker did not know it is not the same claim at all. settle() in
			-- particular deliberately asserts no update state, and without this
			-- it would erase one.
			update_state  = CASE WHEN EXCLUDED.report_source = 'agent'
			                       OR EXCLUDED.update_state <> ''
			                     THEN EXCLUDED.update_state
			                     ELSE imaging_machines.update_state END,
			update_error  = CASE WHEN EXCLUDED.report_source = 'agent'
			                       OR EXCLUDED.update_error <> ''
			                     THEN EXCLUDED.update_error
			                     ELSE imaging_machines.update_error END,
			update_rollout= CASE WHEN EXCLUDED.report_source = 'agent'
			                       OR EXCLUDED.update_rollout <> ''
			                     THEN EXCLUDED.update_rollout
			                     ELSE imaging_machines.update_rollout END,
			reported_by   = EXCLUDED.reported_by,
			report_source = EXCLUDED.report_source,
			-- The two moments that bracket an imaging run, and the only record
			-- that answers "did it come back". Written when supplied and kept
			-- otherwise, so an ordinary heartbeat does not erase them and a
			-- re-imaged machine gets the new dates rather than keeping the old.
			imaged_at     = COALESCE(EXCLUDED.imaged_at, imaging_machines.imaged_at),
			booted_at     = COALESCE(EXCLUDED.booted_at, imaging_machines.booted_at),
			last_seen     = now()
		RETURNING `+machineCols,
		m.ID, m.Hostname, m.Address, m.Slot, m.Version, m.Image, m.Arch,
		m.AgentVersion, m.BootID, m.Health, m.UpdateState, m.UpdateError,
		m.UpdateRollout, m.ReportedBy, m.ReportSource, m.ImagedAt, m.BootedAt)
	return scanMachine(row)
}

// MachinesImagedFrom returns the machines imaged from a given image, by the
// image's bare name.
//
// This is what connects a LUKS recovery credential to the machines it actually
// opens, and the connection is not obvious: a machine's LUKS header is written
// once, at imaging time, and an update never touches it. RAUC writes THROUGH
// /dev/mapper/luks-rootfs-*, so a bundle built from a newer image replaces the
// operating system and leaves the keyslots exactly as the original image made
// them. A machine therefore keeps the passphrase of the image it was IMAGED
// from, for as long as it lives, regardless of what it is running now.
//
// So deleting the credential for an old image because the fleet has "moved on"
// throws away the only recovery key for every machine imaged from it — and
// nothing about that machine's current version hints at which credential it
// needs.
//
// The normalisation mirrors secretNameForImage in the imaging package, which is
// what filed the credential: take the basename, drop one compression suffix.
// Machines record the URL they were imaged from
// (http://host/images/x.img.zst); credentials are filed under the bare name
// (x.img). If these two ever disagree the join silently returns nothing, which
// is why a test pins them together.
func (s *Store) MachinesImagedFrom(ctx context.Context, image string) ([]models.ImagingMachine, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+machineCols+`
		  FROM imaging_machines
		 WHERE regexp_replace(regexp_replace(image, '^.*/', ''), '[.](zst|gz)$', '') = $1
		 ORDER BY imaged_at NULLS LAST, id`, image)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ImagingMachine
	for rows.Next() {
		m, serr := scanMachine(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (s *Store) ListMachines(ctx context.Context) ([]models.ImagingMachine, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+machineCols+
		` FROM imaging_machines ORDER BY last_seen DESC NULLS LAST, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ImagingMachine
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

func (s *Store) GetMachine(ctx context.Context, id string) (*models.ImagingMachine, error) {
	return scanMachine(s.pool.QueryRow(ctx,
		`SELECT `+machineCols+` FROM imaging_machines WHERE id=$1`, id))
}

// LinkMachine pins a machine to a host, or clears the pin with a nil host.
//
// The unique index means a host can own at most one machine; re-linking a host
// to a different machine clears the old one first rather than failing, because
// re-imaging a machine under a new identity is a normal thing to do and the
// operator's intent is unambiguous.
func (s *Store) LinkMachine(ctx context.Context, machineID string, hostID *uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op
	if hostID != nil {
		if _, err := tx.Exec(ctx,
			`UPDATE imaging_machines SET host_id=NULL WHERE host_id=$1 AND id<>$2`,
			*hostID, machineID); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(ctx,
		`UPDATE imaging_machines SET host_id=$2 WHERE id=$1`, machineID, hostID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SetMachineOperatorFields writes the half of a machine record that belongs to a
// person rather than to the machine.
func (s *Store) SetMachineOperatorFields(ctx context.Context, id, label string, held bool) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE imaging_machines SET label=$2, held=$3 WHERE id=$1`, id, label, held)
	return err
}

// DeleteMachine forgets a machine entirely.
//
// For a machine that is gone -- decommissioned, reimaged under a different MAC,
// or a row created by a test boot that will never come back. The imaging_events
// rows cascade with it (0080: machine_id REFERENCES imaging_machines ON DELETE
// CASCADE), which is the intent: the record exists to describe a machine, and
// keeping the history of one nobody can point at is how the Machines tab fills
// with rows an operator cannot act on.
//
// Deliberately NOT a soft delete. A machine that still exists reports in again
// and is recreated by ReportMachine on its next heartbeat, so a wrong deletion
// costs a heartbeat interval rather than being permanent -- and a tombstone that
// suppressed that would turn a recoverable mistake into an unrecoverable one.
//
// Returns whether a row was actually removed, so the caller can 404 rather than
// silently report success for an id that was never there.
func (s *Store) DeleteMachine(ctx context.Context, id string) (bool, error) {
	tag, err := s.pool.Exec(ctx, `DELETE FROM imaging_machines WHERE id=$1`, id)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// RecordImagingEvent appends to the provisioning record: what was handed to a
// machine and whether it came back. Append-only, and never fails a caller --
// losing a record must not fail the imaging run it describes.
func (s *Store) RecordImagingEvent(ctx context.Context, machineID, event string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	// tenant_id is omitted throughout this file: the column's DEFAULT is
	// prov_current_tenant(), which resolves the request's tenant, the provider
	// tenant under bypass, and the background contexts a machine's heartbeat
	// arrives in. Supplying it here meant a second implementation of that rule,
	// and it was wrong -- it cast 'bypass' straight to uuid, so every write
	// failed on the single-tenant configuration nearly everyone runs.
	_, _ = s.pool.Exec(ctx, `INSERT INTO imaging_events (machine_id, event, detail)
		VALUES ($1, $2, $3)`, machineID, event, detail)
}

// --- rollouts ----------------------------------------------------------------

const rolloutCols = `id, bundle, version, bundle_url, description, state, halt_reason,
	target_groups, target_hosts, target_all, canary, batch_size, soak_seconds,
	max_failures, window_start, window_end, window_days, canary_done_at,
	failure_baseline, created_at, created_by_name`

func scanRollout(row pgx.Row) (*models.ImagingRollout, error) {
	var r models.ImagingRollout
	err := row.Scan(&r.ID, &r.Bundle, &r.Version, &r.BundleURL, &r.Description,
		&r.State, &r.HaltReason, &r.TargetGroups, &r.TargetHosts, &r.TargetAll,
		&r.Canary, &r.BatchSize, &r.SoakSeconds, &r.MaxFailures,
		&r.WindowStart, &r.WindowEnd, &r.WindowDays, &r.CanaryDoneAt,
		&r.FailureBaseline, &r.CreatedAt, &r.CreatedByName)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) CreateRollout(ctx context.Context, r *models.ImagingRollout, by *uuid.UUID) (*models.ImagingRollout, error) {
	// A nil Go slice is SQL NULL, and these columns are NOT NULL. Their DEFAULT
	// '{}' does not save us: a default applies only when the column is left out
	// of the INSERT, and this statement names it and passes the value. So the
	// most ordinary rollout there is -- target the whole fleet, name no groups --
	// failed on a not-null violation.
	//
	// Coerced here rather than in the handler because it is the SQL that has the
	// requirement, and a second caller would otherwise have to know about it.
	groups, hosts := r.TargetGroups, r.TargetHosts
	if groups == nil {
		groups = []uuid.UUID{}
	}
	if hosts == nil {
		hosts = []uuid.UUID{}
	}
	return scanRollout(s.pool.QueryRow(ctx, `
		INSERT INTO imaging_rollouts (bundle, version, bundle_url, description,
			target_groups, target_hosts, target_all, canary, batch_size, soak_seconds,
			max_failures, window_start, window_end, window_days, created_by, created_by_name)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING `+rolloutCols,
		r.Bundle, r.Version, r.BundleURL, r.Description,
		groups, hosts, r.TargetAll,
		r.Canary, r.BatchSize, r.SoakSeconds, r.MaxFailures,
		r.WindowStart, r.WindowEnd, r.WindowDays, by, r.CreatedByName))
}

func (s *Store) GetRollout(ctx context.Context, id uuid.UUID) (*models.ImagingRollout, error) {
	return scanRollout(s.pool.QueryRow(ctx,
		`SELECT `+rolloutCols+` FROM imaging_rollouts WHERE id=$1`, id))
}

func (s *Store) ListRollouts(ctx context.Context) ([]models.ImagingRollout, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+rolloutCols+
		` FROM imaging_rollouts ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ImagingRollout
	for rows.Next() {
		r, err := scanRollout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// SaveRolloutProgress writes back whatever the engine changed: the rollout's own
// state and every machine's place in it, in one transaction.
//
// One transaction because a rollout that halted and a machine that failed are
// the same decision, and a crash between them would leave a rollout running with
// a failure it has already forgotten to count.
func (s *Store) SaveRolloutProgress(ctx context.Context, r *models.ImagingRollout,
	machines map[string]models.RolloutProgress) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // rollback after commit is a no-op

	if _, err := tx.Exec(ctx, `UPDATE imaging_rollouts
		SET state=$2, halt_reason=$3, canary_done_at=$4, failure_baseline=$5
		WHERE id=$1`, r.ID, r.State, r.HaltReason, r.CanaryDoneAt, r.FailureBaseline); err != nil {
		return err
	}
	for id, p := range machines {
		if _, err := tx.Exec(ctx, `
			INSERT INTO imaging_rollout_machines (rollout_id, machine_id, state, error, attempts, changed_at)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (rollout_id, machine_id) DO UPDATE SET
				state=EXCLUDED.state, error=EXCLUDED.error,
				attempts=EXCLUDED.attempts, changed_at=EXCLUDED.changed_at`,
			r.ID, id, p.State, p.Error, p.Attempts, p.ChangedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func (s *Store) RolloutProgress(ctx context.Context, id uuid.UUID) (map[string]models.RolloutProgress, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT machine_id, state, error, attempts, changed_at
		   FROM imaging_rollout_machines WHERE rollout_id=$1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]models.RolloutProgress{}
	for rows.Next() {
		var mid string
		var p models.RolloutProgress
		if err := rows.Scan(&mid, &p.State, &p.Error, &p.Attempts, &p.ChangedAt); err != nil {
			return nil, err
		}
		out[mid] = p
	}
	return out, rows.Err()
}

func (s *Store) SetRolloutState(ctx context.Context, id uuid.UUID, state, reason string, baseline int) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE imaging_rollouts SET state=$2, halt_reason=$3, failure_baseline=$4 WHERE id=$1`,
		id, state, reason, baseline)
	return err
}

func (s *Store) DeleteRollout(ctx context.Context, id uuid.UUID) error {
	// Matching nothing is a failure, not a no-op: a rollout reported deleted may still be mid-flight.
	tag, err := s.pool.Exec(ctx, `DELETE FROM imaging_rollouts WHERE id=$1`, id)
	return changed(tag, err)
}

// MachinesForTarget resolves a rollout's target to machine ids, now.
//
// Resolved live rather than frozen when the rollout was created: a machine
// enrolled into a group today should be picked up by a rollout that started
// yesterday and has not finished, because otherwise the fleet drifts out of the
// state somebody deliberately put it in and nothing says so.
//
// Targets are host groups -- this product's own, not a second set naming the
// same machines. That is the largest simplification joining the two products
// buys, and the reason a machine must be linked to a host to be in a group
// rollout at all.
func (s *Store) MachinesForTarget(ctx context.Context, groups, hosts []uuid.UUID, all bool) ([]string, error) {
	if all {
		rows, err := s.pool.Query(ctx, `SELECT id FROM imaging_machines ORDER BY id`)
		return collectIDs(rows, err)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT m.id FROM imaging_machines m
		 WHERE m.host_id = ANY($2)
		    OR m.host_id IN (SELECT hg.host_id FROM host_groups hg WHERE hg.group_id = ANY($1))
		 ORDER BY m.id`, groups, hosts)
	return collectIDs(rows, err)
}

func collectIDs(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// LastImagingEvent is when a machine was last recorded doing something, used to
// fill in imaged_at / booted_at on the fleet view without a second table scan.
func (s *Store) LastImagingEvent(ctx context.Context, machineID, event string) (*time.Time, error) {
	var at time.Time
	err := s.pool.QueryRow(ctx,
		`SELECT created_at FROM imaging_events WHERE machine_id=$1 AND event=$2
		  ORDER BY created_at DESC LIMIT 1`, machineID, event).Scan(&at)
	if err != nil {
		return nil, err
	}
	return &at, nil
}
