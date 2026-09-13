package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ContainerStack is the desired state of one stack on one host.
type ContainerStack struct {
	ID       uuid.UUID `json:"id"`
	HostID   uuid.UUID `json:"hostId"`
	Hostname string    `json:"hostname,omitempty"`
	Name     string    `json:"name"`
	Compose  string    `json:"compose,omitempty"`
	Path     string    `json:"path"`
	Revision int       `json:"revision"`
	Enabled  bool      `json:"enabled"`
	// Deployed is what the host last confirmed it applied. Separate from Revision
	// so "should be running" and "is running" cannot be read as the same thing.
	Deployed     *int       `json:"deployedRevision,omitempty"`
	DeployState  string     `json:"deployState,omitempty"`
	DeployDetail string     `json:"deployDetail,omitempty"`
	DeployedAt   *time.Time `json:"deployedAt,omitempty"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

// StackRevision is one recorded change to a stack: what it became, who changed
// it and why. This is what replaces `git log` when the definitions move out of a
// repository.
type StackRevision struct {
	Revision   int       `json:"revision"`
	Compose    string    `json:"compose,omitempty"`
	Note       string    `json:"note,omitempty"`
	AuthorName string    `json:"authorName,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
}

// stackRoot is where a stack's rendered files live on the host unless the stack
// names somewhere else. /opt/stacks because that is where these already are on
// this fleet -- adopting an existing layout beats imposing a new one and leaving
// the old files orphaned.
const stackRoot = "/opt/stacks"

// ValidStackName reports whether a name is safe to use as a directory.
//
// The name is interpolated into a path that a privileged process then writes to,
// so it may not escape, hide, or reach anywhere the operator did not name. A
// stack called ".." or "a/b" is not a naming inconvenience; it is a write to
// somewhere else on the host.
func ValidStackName(name string) bool {
	if name == "" || len(name) > 64 || name == "." || name == ".." {
		return false
	}
	if strings.ContainsAny(name, `/\:`+"\x00") || strings.HasPrefix(name, ".") {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

// resolveStackPath decides where a stack's files live, given what the caller
// said and what is already stored.
//
// An empty input path means "the caller is not saying where this lives", NOT
// "move it under /opt/stacks". Those read the same at the call site and are
// opposite in effect: the compose editor sends only the text, so treating its
// silence as a choice relocated an adopted stack from /home/keith/media-stack to
// a fresh directory holding nothing but the compose file. The next deploy wrote
// there, found no .env, and reported the operator's compose file as invalid.
//
// So the default belongs to creation alone, where there is no stored path to
// keep and something has to be chosen.
func resolveStackPath(inPath, prevPath, name string) string {
	if p := strings.TrimSpace(inPath); p != "" {
		return p
	}
	if prevPath != "" {
		return prevPath
	}
	return stackRoot + "/" + name
}

// StackInput creates or updates a stack.
type StackInput struct {
	HostID     uuid.UUID
	Name       string
	Compose    string
	Path       string
	Note       string
	AuthorID   *uuid.UUID
	AuthorName string
}

var ErrInvalidStackName = errors.New("a stack name may contain only letters, digits, dash, underscore and dot, and may not start with a dot")

// UpsertStack records a stack definition and, when the compose actually changed,
// a new revision.
//
// A revision per SAVE rather than per change would fill the history with entries
// that changed nothing, and the history is the thing standing in for a git log --
// it has to be worth reading.
func (s *Store) UpsertStack(ctx context.Context, in StackInput) (*ContainerStack, error) {
	if !ValidStackName(in.Name) {
		return nil, ErrInvalidStackName
	}
	inPath := strings.TrimSpace(in.Path)
	var st ContainerStack
	err := s.tx(ctx, func(tx pgx.Tx) error {
		var prevCompose, prevPath string
		var id uuid.UUID
		var rev int
		err := tx.QueryRow(ctx,
			`SELECT id, compose, path, revision FROM container_stacks WHERE host_id=$1 AND name=$2`,
			in.HostID, in.Name).Scan(&id, &prevCompose, &prevPath, &rev)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			path := resolveStackPath(inPath, "", in.Name)
			if err := tx.QueryRow(ctx, `
				INSERT INTO container_stacks (host_id, name, compose, path, revision)
				VALUES ($1,$2,$3,$4,1) RETURNING id, revision`,
				in.HostID, in.Name, in.Compose, path).Scan(&id, &rev); err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			path := resolveStackPath(inPath, prevPath, in.Name)
			if prevCompose == in.Compose && path == prevPath {
				return nil // nothing changed
			}
			next := rev
			if prevCompose != in.Compose {
				next = rev + 1
			}
			if _, err := tx.Exec(ctx, `
				UPDATE container_stacks SET compose=$2, path=$3, revision=$4, updated_at=now()
				WHERE id=$1`, id, in.Compose, path, next); err != nil {
				return err
			}
			rev = next
			if prevCompose == in.Compose {
				return nil // path-only change: no new revision to record
			}
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO container_stack_revisions
				(stack_id, revision, compose, note, author_id, author_name)
			VALUES ($1,$2,$3,$4,$5,$6)
			ON CONFLICT (stack_id, revision) DO NOTHING`,
			id, rev, in.Compose, in.Note, in.AuthorID, in.AuthorName)
		return err
	})
	if err != nil {
		return nil, err
	}
	got, err := s.StackByHostName(ctx, in.HostID, in.Name)
	if err != nil {
		return nil, err
	}
	st = *got
	return &st, nil
}

const stackCols = `s.id, s.host_id, COALESCE(h.hostname,''), s.name, s.compose, s.path,
	s.revision, s.enabled, d.revision, COALESCE(d.state,''), COALESCE(d.detail,''),
	d.applied_at, s.created_at, s.updated_at`

const stackFrom = `container_stacks s
	LEFT JOIN hosts h ON h.id = s.host_id
	LEFT JOIN container_stack_deployments d ON d.stack_id = s.id`

func scanStack(row pgx.Row) (*ContainerStack, error) {
	var st ContainerStack
	if err := row.Scan(&st.ID, &st.HostID, &st.Hostname, &st.Name, &st.Compose, &st.Path,
		&st.Revision, &st.Enabled, &st.Deployed, &st.DeployState, &st.DeployDetail,
		&st.DeployedAt, &st.CreatedAt, &st.UpdatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	return &st, nil
}

// StackByHostName loads one stack.
func (s *Store) StackByHostName(ctx context.Context, hostID uuid.UUID, name string) (*ContainerStack, error) {
	return scanStack(s.pool.QueryRow(ctx,
		`SELECT `+stackCols+` FROM `+stackFrom+` WHERE s.host_id=$1 AND s.name=$2`, hostID, name))
}

// GetStack loads one stack by id.
func (s *Store) GetStack(ctx context.Context, id uuid.UUID) (*ContainerStack, error) {
	return scanStack(s.pool.QueryRow(ctx,
		`SELECT `+stackCols+` FROM `+stackFrom+` WHERE s.id=$1`, id))
}

// ListStacks returns every stack, or those for one host.
func (s *Store) ListStacks(ctx context.Context, hostID *uuid.UUID) ([]ContainerStack, error) {
	q := `SELECT ` + stackCols + ` FROM ` + stackFrom
	args := []any{}
	if hostID != nil {
		q += ` WHERE s.host_id=$1`
		args = append(args, *hostID)
	}
	q += ` ORDER BY COALESCE(h.hostname,''), s.name`
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ContainerStack{}
	for rows.Next() {
		st, err := scanStack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *st)
	}
	return out, rows.Err()
}

// StackHistory returns a stack's revisions, newest first.
func (s *Store) StackHistory(ctx context.Context, stackID uuid.UUID, limit int) ([]StackRevision, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT revision, compose, note, author_name, created_at
		FROM container_stack_revisions WHERE stack_id=$1
		ORDER BY revision DESC LIMIT $2`, stackID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []StackRevision{}
	for rows.Next() {
		var r StackRevision
		if err := rows.Scan(&r.Revision, &r.Compose, &r.Note, &r.AuthorName, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordStackDeployment records what a host confirmed it applied.
func (s *Store) RecordStackDeployment(ctx context.Context, stackID uuid.UUID, revision int, state, detail string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO container_stack_deployments (stack_id, revision, state, detail, applied_at)
		VALUES ($1,$2,$3,$4, now())
		ON CONFLICT (stack_id) DO UPDATE SET
			revision=EXCLUDED.revision, state=EXCLUDED.state,
			detail=EXCLUDED.detail, applied_at=now()`,
		stackID, revision, state, truncateStr(detail, 2000))
	return err
}

// MarkStackDeploying records that a deploy has started, WITHOUT touching the
// revision the host is known to be running.
//
// That distinction is the whole point. RecordStackDeployment overwrites the
// revision, so using it to mark a start would record the host as running the
// target before it is -- and a deploy that pulls eight images takes minutes, all
// of which would be spent claiming a success that had not happened. The host is
// still on whatever it was on until the deploy says otherwise.
//
// On a stack that has never deployed there is no prior revision, so 0 stands for
// "none": the state says deploying, and if it fails the row reads "failed at r0",
// which is true -- nothing has ever been deployed.
func (s *Store) MarkStackDeploying(ctx context.Context, stackID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO container_stack_deployments (stack_id, revision, state, detail, applied_at)
		VALUES ($1, 0, 'deploying', '', now())
		ON CONFLICT (stack_id) DO UPDATE SET
			state='deploying', detail='', applied_at=now()`,
		stackID)
	return err
}

// DeleteStack removes a definition. It does NOT stop what is running: taking a
// stack out of the inventory and tearing it down on the host are different
// intentions, and conflating them would make forgetting to record something a
// way to destroy it.
func (s *Store) DeleteStack(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM container_stacks WHERE id=$1`, id)
	return err
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
