package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// VaultVersionSeal is one sealed vault-secret version, for the FIPS re-seal sweep.
type VaultVersionSeal struct {
	ID     uuid.UUID
	Sealed string
}

// AllVaultVersionSeals returns every stored vault-secret version's sealed payload, so
// the FIPS migration can re-KDF each in place. Read-only.
func (s *Store) AllVaultVersionSeals(ctx context.Context) ([]VaultVersionSeal, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, sealed FROM vault_secret_versions`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VaultVersionSeal
	for rows.Next() {
		var v VaultVersionSeal
		if err := rows.Scan(&v.ID, &v.Sealed); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// UpdateVaultVersionSeal replaces a version's sealed payload IN PLACE (a KDF re-wrap
// is not a value change, so it must not create a new version). Used by the FIPS sweep.
func (s *Store) UpdateVaultVersionSeal(ctx context.Context, id uuid.UUID, sealed string) error {
	_, err := s.pool.Exec(ctx, `UPDATE vault_secret_versions SET sealed=$2 WHERE id=$1`, id, sealed)
	return err
}

// VaultSecretInput is the metadata for creating a credential.
type VaultSecretInput struct {
	Name         string
	Folder       string
	Type         string
	Username     string
	Target       string
	Description  string
	AccessPolicy string
	CreatedBy    uuid.UUID
}

func (in VaultSecretInput) accessPolicy() string {
	switch in.AccessPolicy {
	case "checkout", "approval":
		return in.AccessPolicy
	default:
		return "open"
	}
}

const vaultSecretCols = `s.id, s.name, s.folder, s.type, s.username, s.target, s.description, s.access_policy, s.version,
	COALESCE(u.username,''), s.created_at, s.updated_at, s.rotation_interval_days, s.last_rotated_at, s.next_rotation_at`

func scanVaultSecret(row interface{ Scan(...any) error }) (*models.VaultSecret, error) {
	var v models.VaultSecret
	if err := row.Scan(&v.ID, &v.Name, &v.Folder, &v.Type, &v.Username, &v.Target, &v.Description,
		&v.AccessPolicy, &v.Version, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt,
		&v.RotationIntervalDays, &v.LastRotatedAt, &v.NextRotationAt); err != nil {
		return nil, err
	}
	return &v, nil
}

// SetVaultRotationPolicy sets (or clears, with days=0) automatic rotation for a
// credential. Setting a policy schedules the next rotation one interval out; the
// on-demand rotate endpoint independently refreshes next_rotation_at via MarkVaultRotated.
func (s *Store) SetVaultRotationPolicy(ctx context.Context, id uuid.UUID, days int) error {
	if days < 0 {
		days = 0
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE vault_secrets
		SET rotation_interval_days = $2,
		    next_rotation_at = CASE WHEN $2 > 0
		        THEN COALESCE(last_rotated_at, now()) + ($2 || ' days')::interval
		        ELSE NULL END,
		    updated_at = now()
		WHERE id = $1`, id, days)
	return err
}

// MarkVaultRotated records a successful rotation and schedules the next one.
func (s *Store) MarkVaultRotated(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE vault_secrets
		SET last_rotated_at = $2::timestamptz,
		    next_rotation_at = CASE WHEN rotation_interval_days > 0
		        THEN $2::timestamptz + (rotation_interval_days || ' days')::interval ELSE NULL END,
		    updated_at = now()
		WHERE id = $1`, id, at)
	return err
}

// DeferVaultRotation pushes a credential's next scheduled rotation one interval into
// the future WITHOUT recording a successful rotation. The loop calls this after a
// failed attempt so it backs off (retries at the next scheduled time) instead of
// hammering a broken credential every check cycle.
func (s *Store) DeferVaultRotation(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE vault_secrets
		SET next_rotation_at = CASE WHEN rotation_interval_days > 0
		        THEN now() + (rotation_interval_days || ' days')::interval ELSE NULL END,
		    updated_at = now()
		WHERE id = $1`, id)
	return err
}

// DueVaultRotations returns password credentials whose automatic rotation is due
// (policy set and next_rotation_at reached). Only password credentials can be
// rotated automatically.
func (s *Store) DueVaultRotations(ctx context.Context, now time.Time) ([]models.VaultSecret, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+vaultSecretCols+`
		FROM vault_secrets s LEFT JOIN users u ON u.id = s.created_by
		WHERE s.type = 'password' AND s.rotation_interval_days > 0
		  AND s.next_rotation_at IS NOT NULL AND s.next_rotation_at <= $1
		ORDER BY s.next_rotation_at`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.VaultSecret
	for rows.Next() {
		v, err := scanVaultSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// CreateVaultSecret inserts a credential and its first sealed version in one tx.
func (s *Store) CreateVaultSecret(ctx context.Context, in VaultSecretInput, sealed string) (*models.VaultSecret, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var id uuid.UUID
	if err := tx.QueryRow(ctx, `
		INSERT INTO vault_secrets (name, folder, type, username, target, description, access_policy, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		in.Name, in.Folder, in.Type, in.Username, in.Target, in.Description, in.accessPolicy(), in.CreatedBy).Scan(&id); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO vault_secret_versions (secret_id, version, sealed, created_by)
		VALUES ($1, 1, $2, $3)`, id, sealed, in.CreatedBy); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return s.GetVaultSecret(ctx, id)
}

// AddVaultSecretVersion stores a new sealed version and advances the secret's
// current version (rotation / value change). Returns the new version number.
func (s *Store) AddVaultSecretVersion(ctx context.Context, secretID uuid.UUID, sealed string, createdBy uuid.UUID) (int, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	var next int
	if err := tx.QueryRow(ctx, `
		UPDATE vault_secrets SET version = version + 1, updated_at = now() WHERE id=$1 RETURNING version`,
		secretID).Scan(&next); err != nil {
		return 0, err
	}
	// Inherit the parent secret's tenant_id explicitly (so an unattended/system
	// rotation running under RLS bypass still tags the version to the right tenant),
	// and NULL created_by when the writer is the system (zero UUID), not a user.
	if _, err := tx.Exec(ctx, `
		INSERT INTO vault_secret_versions (secret_id, version, sealed, created_by, tenant_id)
		SELECT $1, $2, $3, NULLIF($4, '00000000-0000-0000-0000-000000000000'::uuid), s.tenant_id
		FROM vault_secrets s WHERE s.id = $1`,
		secretID, next, sealed, createdBy); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return next, nil
}

// GetVaultSecret returns a credential's metadata (no secret material).
func (s *Store) GetVaultSecret(ctx context.Context, id uuid.UUID) (*models.VaultSecret, error) {
	row := s.pool.QueryRow(ctx, `SELECT `+vaultSecretCols+`
		FROM vault_secrets s LEFT JOIN users u ON u.id = s.created_by WHERE s.id=$1`, id)
	return scanVaultSecret(row)
}

// GetVaultSecretSealed returns the sealed payload of a secret's current version.
func (s *Store) GetVaultSecretSealed(ctx context.Context, id uuid.UUID) (string, error) {
	var sealed string
	err := s.pool.QueryRow(ctx, `
		SELECT v.sealed FROM vault_secret_versions v
		JOIN vault_secrets s ON s.id = v.secret_id AND s.version = v.version
		WHERE v.secret_id=$1`, id).Scan(&sealed)
	return sealed, err
}

// ListAllVaultSecrets returns every credential (for Credential.Manage holders).
func (s *Store) ListAllVaultSecrets(ctx context.Context) ([]models.VaultSecret, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+vaultSecretCols+`
		FROM vault_secrets s LEFT JOIN users u ON u.id = s.created_by ORDER BY s.folder, s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.VaultSecret
	for rows.Next() {
		v, err := scanVaultSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *v)
	}
	return out, rows.Err()
}

// ListAccessibleVaultSecrets returns credentials the user has a grant on (direct
// or via a group), deduped with the caller's HIGHEST effective access per secret.
func (s *Store) ListAccessibleVaultSecrets(ctx context.Context, userID uuid.UUID) ([]models.VaultSecret, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+vaultSecretCols+`, g.access
		FROM vault_secrets s
		LEFT JOIN users u ON u.id = s.created_by
		JOIN vault_grants g ON g.secret_id = s.id
		WHERE (g.subject_kind='user' AND g.subject_id=$1)
		   OR (g.subject_kind='group' AND g.subject_id IN (SELECT group_id FROM user_groups WHERE user_id=$1))
		ORDER BY s.folder, s.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byID := map[uuid.UUID]int{} // secret id -> index in out
	var out []models.VaultSecret
	for rows.Next() {
		var v models.VaultSecret
		var access string
		if err := rows.Scan(&v.ID, &v.Name, &v.Folder, &v.Type, &v.Username, &v.Target, &v.Description,
			&v.AccessPolicy, &v.Version, &v.CreatedBy, &v.CreatedAt, &v.UpdatedAt, &access); err != nil {
			return nil, err
		}
		if i, ok := byID[v.ID]; ok {
			if accessRank(access) > accessRank(out[i].Access) {
				out[i].Access = access
			}
			continue
		}
		v.Access = access
		byID[v.ID] = len(out)
		out = append(out, v)
	}
	return out, rows.Err()
}

// UpdateVaultSecretMeta updates a credential's metadata (not its secret material).
func (s *Store) UpdateVaultSecretMeta(ctx context.Context, id uuid.UUID, in VaultSecretInput) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE vault_secrets SET name=$2, folder=$3, type=$4, username=$5, target=$6, description=$7, access_policy=$8, updated_at=now()
		WHERE id=$1`, id, in.Name, in.Folder, in.Type, in.Username, in.Target, in.Description, in.accessPolicy())
	return err
}

// DeleteVaultSecret removes a credential and all its versions/grants (cascade).
func (s *Store) DeleteVaultSecret(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM vault_secrets WHERE id=$1`, id)
	return err
}

// UserSecretAccess returns the highest access level (view|use|manage) a user has
// on a secret via a direct or group grant, or "" if none.
func (s *Store) UserSecretAccess(ctx context.Context, userID, secretID uuid.UUID) (string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT access FROM vault_grants
		WHERE secret_id=$1 AND (
			(subject_kind='user' AND subject_id=$2)
			OR (subject_kind='group' AND subject_id IN (SELECT group_id FROM user_groups WHERE user_id=$2)))`,
		secretID, userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	best := ""
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return "", err
		}
		if accessRank(a) > accessRank(best) {
			best = a
		}
	}
	return best, rows.Err()
}

// accessRank orders access levels so the highest can be selected. view < use < manage.
func accessRank(a string) int {
	switch a {
	case "manage":
		return 3
	case "use":
		return 2
	case "view":
		return 1
	default:
		return 0
	}
}

// ---- grants ----------------------------------------------------------------

// ListVaultGrants returns a secret's grants with resolved subject names.
func (s *Store) ListVaultGrants(ctx context.Context, secretID uuid.UUID) ([]models.VaultGrant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT g.id, g.secret_id, g.subject_kind, g.subject_id, g.access, g.created_at,
		       COALESCE(u.username, gr.name, '')
		FROM vault_grants g
		LEFT JOIN users u  ON g.subject_kind='user'  AND u.id  = g.subject_id
		LEFT JOIN groups gr ON g.subject_kind='group' AND gr.id = g.subject_id
		WHERE g.secret_id=$1 ORDER BY g.created_at`, secretID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.VaultGrant
	for rows.Next() {
		var g models.VaultGrant
		if err := rows.Scan(&g.ID, &g.SecretID, &g.SubjectKind, &g.SubjectID, &g.Access, &g.CreatedAt, &g.SubjectName); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateVaultGrant grants (or updates) a subject's access to a secret.
func (s *Store) CreateVaultGrant(ctx context.Context, secretID uuid.UUID, kind string, subjectID uuid.UUID, access string) (*models.VaultGrant, error) {
	var g models.VaultGrant
	err := s.pool.QueryRow(ctx, `
		INSERT INTO vault_grants (secret_id, subject_kind, subject_id, access)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (secret_id, subject_kind, subject_id) DO UPDATE SET access=EXCLUDED.access
		RETURNING id, secret_id, subject_kind, subject_id, access, created_at`,
		secretID, kind, subjectID, access).Scan(&g.ID, &g.SecretID, &g.SubjectKind, &g.SubjectID, &g.Access, &g.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// DeleteVaultGrant removes a grant.
func (s *Store) DeleteVaultGrant(ctx context.Context, secretID, grantID uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM vault_grants WHERE id=$1 AND secret_id=$2`, grantID, secretID)
	return err
}

// HostsUsingCredential returns the hosts that authenticate with a given vault
// credential (used to know where to rotate it).
func (s *Store) HostsUsingCredential(ctx context.Context, credentialID uuid.UUID) ([]models.Host, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+hostCols+` FROM hosts WHERE credential_id=$1 ORDER BY hostname`, credentialID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *h)
	}
	return out, rows.Err()
}
