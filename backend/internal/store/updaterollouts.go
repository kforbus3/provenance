package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kforbus3/provenance/backend/internal/composefile"
)

// UpdateRollout is a staged rollout of one container image update.
type UpdateRollout struct {
	ID           uuid.UUID `json:"id"`
	Repository   string    `json:"repository"`
	FromTag      string    `json:"fromTag"`
	ToTag        string    `json:"toTag"`
	TargetDigest string    `json:"targetDigest,omitempty"`

	State      string `json:"state"`
	HaltReason string `json:"haltReason,omitempty"`

	Canary      int `json:"canary"`
	BatchSize   int `json:"batchSize"`
	SoakSeconds int `json:"soakSeconds"`
	MaxFailures int `json:"maxFailures"`

	WindowStart *string `json:"windowStart,omitempty"`
	WindowEnd   *string `json:"windowEnd,omitempty"`
	WindowDays  []int32 `json:"windowDays,omitempty"`

	CanaryDoneAt *time.Time `json:"canaryDoneAt,omitempty"`

	CreatedAt     time.Time `json:"createdAt"`
	CreatedByName string    `json:"createdBy,omitempty"`

	// Images is every image this rollout covers. A single-image rollout has one.
	// Loaded on the detail view; the list carries only the count, because a list
	// of fifty rollouts does not need every image of every one of them.
	Images     []RolloutImage `json:"images,omitempty"`
	ImageCount int            `json:"imageCount,omitempty"`

	// Filled in by the service layer.
	Hosts  []UpdateRolloutHost `json:"hosts,omitempty"`
	Counts map[string]int      `json:"counts,omitempty"`
}

// RolloutImage is one image a rollout covers.
type RolloutImage struct {
	Repository   string `json:"repository"`
	FromTag      string `json:"fromTag"`
	ToTag        string `json:"toTag"`
	TargetDigest string `json:"targetDigest,omitempty"`
}

// UpdateRolloutHost is one host's place in one rollout.
type UpdateRolloutHost struct {
	HostID    uuid.UUID `json:"hostId"`
	Hostname  string    `json:"hostname,omitempty"`
	State     string    `json:"state"`
	Error     string    `json:"error,omitempty"`
	Attempts  int       `json:"attempts"`
	Forgiven  bool      `json:"-"`
	ChangedAt time.Time `json:"changedAt"`
}

const (
	UpdateHostPending  = "pending"
	UpdateHostApplying = "applying"
	UpdateHostVerified = "verified"
	UpdateHostFailed   = "failed"
	UpdateHostSkipped  = "skipped"

	UpdateRolloutRunning   = "running"
	UpdateRolloutPaused    = "paused"
	UpdateRolloutHalted    = "halted"
	UpdateRolloutCompleted = "completed"
	UpdateRolloutCancelled = "cancelled"
)

// CreateUpdateRollout records the intent and enrolls its hosts.
//
// Hosts are enrolled at creation, not discovered as the rollout runs. A rollout
// whose membership changed underneath it could never be "complete", and a host
// that started running the image after the operator approved the change was
// never part of what they approved.
func (s *Store) CreateUpdateRollout(ctx context.Context, r UpdateRollout, hosts []uuid.UUID, createdBy *uuid.UUID) (*UpdateRollout, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var id uuid.UUID
	var createdAt time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO container_update_rollouts
		    (repository, from_tag, to_tag, target_digest, canary, batch_size,
		     soak_seconds, max_failures, window_start, window_end, window_days, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING id, created_at`,
		r.Repository, r.FromTag, r.ToTag, r.TargetDigest, r.Canary, r.BatchSize,
		r.SoakSeconds, r.MaxFailures, r.WindowStart, r.WindowEnd, r.WindowDays, createdBy).
		Scan(&id, &createdAt)
	if err != nil {
		return nil, err
	}
	// Always at least one row, even for a single-image rollout, so the engine has
	// one path to read rather than two that drift.
	images := r.Images
	if len(images) == 0 {
		images = []RolloutImage{{
			Repository: r.Repository, FromTag: r.FromTag,
			ToTag: r.ToTag, TargetDigest: r.TargetDigest,
		}}
	}
	for _, im := range images {
		if _, err := tx.Exec(ctx, `
			INSERT INTO container_update_rollout_images
			    (rollout_id, repository, from_tag, to_tag, target_digest)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
			id, im.Repository, im.FromTag, im.ToTag, im.TargetDigest); err != nil {
			return nil, err
		}
	}
	for _, h := range hosts {
		if _, err := tx.Exec(ctx, `
			INSERT INTO container_update_rollout_hosts (rollout_id, host_id)
			VALUES ($1, $2) ON CONFLICT DO NOTHING`, id, h); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	r.ID = id
	r.CreatedAt = createdAt
	r.State = UpdateRolloutRunning
	return &r, nil
}

const updateRolloutCols = `r.id, r.repository, r.from_tag, r.to_tag, r.target_digest,
	r.state, r.halt_reason, r.canary, r.batch_size, r.soak_seconds, r.max_failures,
	r.window_start, r.window_end, r.window_days, r.canary_done_at, r.created_at,
	COALESCE(u.display_name, u.username, '')`

func scanUpdateRollout(row interface{ Scan(...any) error }) (*UpdateRollout, error) {
	var r UpdateRollout
	err := row.Scan(&r.ID, &r.Repository, &r.FromTag, &r.ToTag, &r.TargetDigest,
		&r.State, &r.HaltReason, &r.Canary, &r.BatchSize, &r.SoakSeconds, &r.MaxFailures,
		&r.WindowStart, &r.WindowEnd, &r.WindowDays, &r.CanaryDoneAt, &r.CreatedAt,
		&r.CreatedByName)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListUpdateRollouts returns every rollout, newest first, with per-state counts.
//
// The counts come with the list rather than only on the detail view because
// without them a rollout in which every host failed still reads as "completed",
// which is the state it is genuinely in and exactly the wrong thing to show on
// its own. A row that can say "completed, 3 of 5 verified" cannot mislead.
func (s *Store) ListUpdateRollouts(ctx context.Context) ([]UpdateRollout, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+updateRolloutCols+`
		FROM container_update_rollouts r
		LEFT JOIN users u ON u.id = r.created_by
		ORDER BY r.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UpdateRollout{}
	for rows.Next() {
		r, err := scanUpdateRollout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// One grouped query for every rollout rather than one per row.
	crows, err := s.pool.Query(ctx, `
		SELECT rh.rollout_id, rh.state, count(*)
		FROM container_update_rollout_hosts rh
		JOIN container_update_rollouts r ON r.id = rh.rollout_id
		GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	counts := map[uuid.UUID]map[string]int{}
	for crows.Next() {
		var id uuid.UUID
		var state string
		var n int
		if err := crows.Scan(&id, &state, &n); err != nil {
			return nil, err
		}
		if counts[id] == nil {
			counts[id] = map[string]int{}
		}
		counts[id][state] = n
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}
	irows, err := s.pool.Query(ctx, `
		SELECT rollout_id, count(*) FROM container_update_rollout_images GROUP BY 1`)
	if err != nil {
		return nil, err
	}
	defer irows.Close()
	imageCounts := map[uuid.UUID]int{}
	for irows.Next() {
		var id uuid.UUID
		var n int
		if err := irows.Scan(&id, &n); err != nil {
			return nil, err
		}
		imageCounts[id] = n
	}
	if err := irows.Err(); err != nil {
		return nil, err
	}

	for i := range out {
		out[i].Counts = counts[out[i].ID]
		out[i].ImageCount = imageCounts[out[i].ID]
	}
	return out, nil
}

// GetUpdateRollout returns one rollout with its hosts.
func (s *Store) GetUpdateRollout(ctx context.Context, id uuid.UUID) (*UpdateRollout, error) {
	r, err := scanUpdateRollout(s.pool.QueryRow(ctx, `
		SELECT `+updateRolloutCols+`
		FROM container_update_rollouts r
		LEFT JOIN users u ON u.id = r.created_by
		WHERE r.id = $1`, id))
	if err != nil {
		return nil, err
	}
	r.Hosts, err = s.UpdateRolloutHosts(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.Images, err = s.RolloutImages(ctx, id); err != nil {
		return nil, err
	}
	r.Counts = map[string]int{}
	for _, h := range r.Hosts {
		r.Counts[h.State]++
	}
	return r, nil
}

// UpdateRolloutHosts returns every host in a rollout.
func (s *Store) UpdateRolloutHosts(ctx context.Context, id uuid.UUID) ([]UpdateRolloutHost, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT rh.host_id, COALESCE(h.hostname,''), rh.state, rh.error, rh.attempts,
		       rh.forgiven, rh.changed_at
		FROM container_update_rollout_hosts rh
		LEFT JOIN hosts h ON h.id = rh.host_id
		WHERE rh.rollout_id = $1
		ORDER BY h.hostname`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UpdateRolloutHost{}
	for rows.Next() {
		var h UpdateRolloutHost
		if err := rows.Scan(&h.HostID, &h.Hostname, &h.State, &h.Error, &h.Attempts,
			&h.Forgiven, &h.ChangedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ActiveUpdateRollouts returns the rollouts the engine should be driving.
func (s *Store) ActiveUpdateRollouts(ctx context.Context) ([]UpdateRollout, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+updateRolloutCols+`
		FROM container_update_rollouts r
		LEFT JOIN users u ON u.id = r.created_by
		WHERE r.state = 'running'
		ORDER BY r.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UpdateRollout{}
	for rows.Next() {
		r, err := scanUpdateRollout(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// SetUpdateRolloutHostState records where a host has got to.
func (s *Store) SetUpdateRolloutHostState(ctx context.Context, rollout, host uuid.UUID, state, errMsg string) error {
	// attempts is NOT touched here. ClaimUpdateRolloutHost is the single place a
	// host starts an attempt and the single place the counter moves; incrementing
	// in both would count every attempt twice and trip an attempt limit at half
	// the number an operator configured.
	_, err := s.pool.Exec(ctx, `
		UPDATE container_update_rollout_hosts
		SET state = $3, error = $4, changed_at = now()
		WHERE rollout_id = $1 AND host_id = $2`, rollout, host, state, errMsg)
	return err
}

// ClaimUpdateRolloutHost moves a host from pending to applying, and reports
// whether THIS caller is the one that moved it.
//
// The conditional update is the point. Two engine ticks overlapping -- a slow
// deploy and the next tick, or two instances if leadership ever flapped -- would
// otherwise both read the host as pending and both deploy to it, which for a
// compose file means two writers racing on the same path.
func (s *Store) ClaimUpdateRolloutHost(ctx context.Context, rollout, host uuid.UUID) (bool, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE container_update_rollout_hosts
		SET state = 'applying', attempts = attempts + 1, changed_at = now()
		WHERE rollout_id = $1 AND host_id = $2 AND state = 'pending'`, rollout, host)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// SetUpdateRolloutState changes a rollout's own state.
func (s *Store) SetUpdateRolloutState(ctx context.Context, id uuid.UUID, state, reason string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE container_update_rollouts SET state = $2, halt_reason = $3 WHERE id = $1`,
		id, state, reason)
	return err
}

// StampUpdateRolloutCanaryDone records when the canary phase finished.
//
// Only if it is not already set: the soak is measured from the END of the canary
// phase, and re-stamping as later hosts verify would restart the soak on every
// batch, so a fleet of any size would never finish.
func (s *Store) StampUpdateRolloutCanaryDone(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE container_update_rollouts SET canary_done_at = $2
		WHERE id = $1 AND canary_done_at IS NULL`, id, at)
	return err
}

// ResumeUpdateRollout restarts a halted or paused rollout, forgiving the
// failures that stopped it.
//
// The hosts that failed stay failed and are marked forgiven, so the budget counts
// from here. Without this a rollout that halted on its budget re-halts on the
// very next tick, and `resume` becomes a button that reports success and does
// nothing -- worse than one that refuses.
func (s *Store) ResumeUpdateRollout(ctx context.Context, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	// Failed hosts go back to PENDING, not merely forgiven.
	//
	// Forgiving a failure stops it counting against the budget. On its own that
	// was the whole of resume — and in a PUSH engine a failed host is never
	// picked up again, so the rollout found nothing pending, nothing in flight,
	// and marked itself completed. Resume reported success and did nothing, for
	// a rollout that had updated no host at all. That is worse than a button
	// that refuses.
	//
	// forgiven and error are cleared with it: the budget now measures failures
	// SINCE the resume, which is what "I have looked at those, carry on" means.
	// Leaving forgiven set would exempt these hosts from the budget forever, so
	// a rollout that kept failing would never halt again.
	//
	// attempts too. Resume is a deliberate act by somebody who has looked at the
	// failure; giving a host that has used its attempts no way back would mean
	// fixing the cause and still being told it had given up.
	if _, err := tx.Exec(ctx, `
		UPDATE container_update_rollout_hosts
		SET state = 'pending', forgiven = FALSE, error = '', attempts = 0, changed_at = now()
		WHERE rollout_id = $1 AND state IN ('failed', 'applying')`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE container_update_rollouts SET state = 'running', halt_reason = ''
		WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// HostsRunningImage returns the hosts running a given repository:tag.
func (s *Store) HostsRunningImage(ctx context.Context, repo, tag string) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT hi.host_id
		FROM host_inventory hi,
		     LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
		WHERE c->>'repository' = $1 AND c->>'tag' = $2`, repo, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// StacksReferencingImage returns the managed stacks on a host whose compose
// mentions a repository, so a rollout can find the file it needs to rewrite.
//
// Matching is done in Go by the caller, on the compose text: a SQL LIKE would
// match "nginx" inside "nginx-extras" and rewrite the wrong service.
func (s *Store) StacksReferencingImage(ctx context.Context, hostID uuid.UUID) ([]ContainerStack, error) {
	return s.ListStacks(ctx, &hostID)
}

// RolloutImages returns every image a rollout covers.
func (s *Store) RolloutImages(ctx context.Context, id uuid.UUID) ([]RolloutImage, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT repository, from_tag, to_tag, target_digest
		FROM container_update_rollout_images
		WHERE rollout_id = $1
		ORDER BY repository, from_tag`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RolloutImage{}
	for rows.Next() {
		var im RolloutImage
		if err := rows.Scan(&im.Repository, &im.FromTag, &im.ToTag, &im.TargetDigest); err != nil {
			return nil, err
		}
		out = append(out, im)
	}
	return out, rows.Err()
}

// HostsRunningAnyImage returns the hosts running any of the given repository:tag
// pairs, once each.
//
// For "update everything that has something available": the rollout covers many
// images, and a host belongs to it if it runs any of them. Resolved once, at
// creation, for the same reason the single-image case is — a rollout whose
// membership changed underneath it could never be complete.
func (s *Store) HostsRunningAnyImage(ctx context.Context, images []RolloutImage) ([]uuid.UUID, error) {
	if len(images) == 0 {
		return nil, nil
	}
	repos := make([]string, 0, len(images))
	tags := make([]string, 0, len(images))
	for _, im := range images {
		repos = append(repos, im.Repository)
		tags = append(tags, im.FromTag)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT hi.host_id
		FROM host_inventory hi,
		     LATERAL jsonb_array_elements(COALESCE(hi.containers, jsonb_build_array())) AS c
		JOIN unnest($1::text[], $2::text[]) AS k(repository, tag)
		  ON k.repository = c->>'repository' AND k.tag = c->>'tag'`,
		repos, tags)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	seen := map[uuid.UUID]bool{}
	for _, id := range out {
		seen[id] = true
	}

	// A host also counts when its own compose file NAMES the tag, even though no
	// container is running it yet.
	//
	// Pinning a compose file to the version a container is already on recreates
	// nothing, so between the pin and the next deploy the file says
	// bazarr:v1.6.0-ls356 while the container is still on :latest. The registry
	// check follows the file -- that is the version an operator chose, and the
	// only one a newer version can be found against -- so the update they are
	// offered names a from-tag no container has. Matching only the running tag
	// answered "no host is running lscr.io/linuxserver/bazarr:v1.6.0-ls356" and
	// refused to create the rollout, for an update the screen had just offered.
	//
	// This is the same rule the ENGINE applies when deciding whether a declared
	// tag counts as one a host runs. The two have to agree, or a rollout is
	// either refused at creation or created and then skipped on every host.
	declared, err := s.hostsDeclaringAnyImage(ctx, images)
	if err != nil {
		return nil, err
	}
	for _, id := range declared {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, rows.Err()
}

// hostsDeclaringAnyImage returns hosts whose enabled stacks name one of these
// repository:tag pairs, restricted to hosts actually running the repository.
//
// The restriction matters: a compose file may name a service that is scaled to
// zero or commented out of the running project, and a rollout must not start
// something nobody asked to start.
func (s *Store) hostsDeclaringAnyImage(ctx context.Context, images []RolloutImage) ([]uuid.UUID, error) {
	// Which repositories each host actually runs.
	runs := map[uuid.UUID]map[string]bool{}
	rows, err := s.pool.Query(ctx, `
		SELECT hi.host_id, c->>'repository'
		FROM host_inventory hi,
		     LATERAL jsonb_array_elements(COALESCE(hi.containers, jsonb_build_array())) AS c
		WHERE COALESCE(c->>'repository','') <> ''`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id uuid.UUID
		var repo string
		if err := rows.Scan(&id, &repo); err != nil {
			rows.Close()
			return nil, err
		}
		if runs[id] == nil {
			runs[id] = map[string]bool{}
		}
		runs[id][repo] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	srows, err := s.pool.Query(ctx, `
		SELECT host_id, compose FROM container_stacks
		WHERE enabled AND COALESCE(compose,'') <> ''`)
	if err != nil {
		return nil, err
	}
	defer srows.Close()
	var stacks []hostCompose
	for srows.Next() {
		var hc hostCompose
		if err := srows.Scan(&hc.HostID, &hc.Compose); err != nil {
			return nil, err
		}
		stacks = append(stacks, hc)
	}
	if err := srows.Err(); err != nil {
		return nil, err
	}
	return matchDeclaringHosts(runs, stacks, images), nil
}

// hostCompose is one enabled stack's text and the host it belongs to.
type hostCompose struct {
	HostID  uuid.UUID
	Compose string
}

// matchDeclaringHosts is the decision, separated from the queries so it can be
// tested without a database: which hosts a rollout applies to when its from-tag
// is one a compose file NAMES rather than one a container is running.
func matchDeclaringHosts(runs map[uuid.UUID]map[string]bool, stacks []hostCompose,
	images []RolloutImage) []uuid.UUID {
	want := map[string]bool{}
	for _, im := range images {
		want[im.Repository+":"+im.FromTag] = true
	}
	out := []uuid.UUID{}
	seen := map[uuid.UUID]bool{}
	for _, st := range stacks {
		if seen[st.HostID] {
			continue
		}
		for _, ref := range composefile.Images(st.Compose) {
			// Restricted to a repository the host actually runs: a compose file
			// may name a service that is scaled to zero or commented out of the
			// running project, and a rollout must not start something nobody
			// asked to start.
			if want[ref.Repository+":"+ref.Tag] && runs[st.HostID][ref.Repository] {
				seen[st.HostID] = true
				out = append(out, st.HostID)
				break
			}
		}
	}
	return out
}

// ErrRolloutNotFinished is returned when a delete is attempted on a rollout that
// is still running or paused.
var ErrRolloutNotFinished = errors.New("this rollout has not finished")

// FinishedUpdateRolloutStates are the states a rollout stops in.
//
// Paused is deliberately absent. It looks inert and is not: the hosts it has
// already claimed are mid-update, and resume is a button somebody may still be
// intending to press.
var FinishedUpdateRolloutStates = []string{
	UpdateRolloutCompleted, UpdateRolloutCancelled, UpdateRolloutHalted,
}

// DeleteUpdateRollout removes a finished rollout and everything recorded under
// it.
//
// The containers it updated are untouched -- this clears history, not state.
// Which is exactly why it refuses a rollout that has NOT finished: deleting one
// mid-flight would strand hosts the engine has already claimed, with nothing
// left to record what happened to them or to report that anything went wrong.
//
// The per-host rows and the image list go with it by ON DELETE CASCADE.
func (s *Store) DeleteUpdateRollout(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM container_update_rollouts WHERE id = $1 AND state = ANY($2)`,
		id, FinishedUpdateRolloutStates)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Either it is gone already or it is still running. Tell those apart, so
		// "already cleared" does not surface as a refusal an operator has to
		// think about.
		var state string
		err := s.pool.QueryRow(ctx,
			`SELECT state FROM container_update_rollouts WHERE id = $1`, id).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // nothing to remove; the caller wanted it gone and it is
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("%w: it is %s", ErrRolloutNotFinished, state)
	}
	return nil
}

// DeleteFinishedUpdateRollouts clears every finished rollout at once, and
// reports how many it removed.
//
// One statement rather than a delete per id from the client: clearing thirty
// rollouts should not be thirty requests that can half-fail and leave the list
// in a state nobody asked for.
func (s *Store) DeleteFinishedUpdateRollouts(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		DELETE FROM container_update_rollouts WHERE state = ANY($1)`,
		FinishedUpdateRolloutStates)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
