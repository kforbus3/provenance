package store

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/models"
)

const sshSessionCols = `id, session_id, user_id, host_id, COALESCE(username,''),
	COALESCE(hostname,''), cert_serial, status, started_at, ended_at, exit_code,
	bytes_in, bytes_out, COALESCE(host(client_ip),'')`

func scanSSHSession(row pgx.Row) (*models.SSHSession, error) {
	var ss models.SSHSession
	err := row.Scan(&ss.ID, &ss.SessionID, &ss.UserID, &ss.HostID, &ss.Username,
		&ss.Hostname, &ss.CertSerial, &ss.Status, &ss.StartedAt, &ss.EndedAt,
		&ss.ExitCode, &ss.BytesIn, &ss.BytesOut, &ss.ClientIP)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &ss, nil
}

// SSHSessionInput carries fields to open an SSH session record.
type SSHSessionInput struct {
	SessionID  *uuid.UUID
	UserID     *uuid.UUID
	HostID     *uuid.UUID
	Username   string
	Hostname   string
	CertSerial *uint64
	ClientIP   string
}

// CreateSSHSession opens an active SSH session record.
func (s *Store) CreateSSHSession(ctx context.Context, in SSHSessionInput) (*models.SSHSession, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO ssh_sessions (session_id, user_id, host_id, username, hostname, cert_serial, client_ip, instance_id)
		VALUES ($1,$2,$3,NULLIF($4,'')::citext,$5,$6,NULLIF($7,'')::inet,$8)
		RETURNING `+sshSessionCols,
		in.SessionID, in.UserID, in.HostID, in.Username, in.Hostname, in.CertSerial, in.ClientIP, s.ownerArg())
	return scanSSHSession(row)
}

// EndSSHSession closes an active session, recording its exit code and byte counts.
func (s *Store) EndSSHSession(ctx context.Context, id uuid.UUID, exitCode int, bytesIn, bytesOut int64) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE ssh_sessions
		SET status=CASE WHEN $2=0 THEN 'closed' ELSE 'error' END,
			ended_at=now(), exit_code=$2, bytes_in=$3, bytes_out=$4
		WHERE id=$1`,
		id, exitCode, bytesIn, bytesOut)
	return err
}

// GetSSHSession loads a single SSH session by id.
func (s *Store) GetSSHSession(ctx context.Context, id uuid.UUID) (*models.SSHSession, error) {
	return scanSSHSession(s.pool.QueryRow(ctx, `SELECT `+sshSessionCols+` FROM ssh_sessions WHERE id=$1`, id))
}

// SSHSessionFilter narrows a session list query.
type SSHSessionFilter struct {
	UserID *uuid.UUID
	HostID *uuid.UUID
	Limit  int
	Offset int
}

// ListSSHSessions returns SSH sessions matching the filter, newest first.
func (s *Store) ListSSHSessions(ctx context.Context, f SSHSessionFilter) ([]models.SSHSession, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+sshSessionCols+`
		FROM ssh_sessions
		WHERE ($1::uuid IS NULL OR user_id=$1) AND ($2::uuid IS NULL OR host_id=$2)
		ORDER BY started_at DESC LIMIT $3 OFFSET $4`,
		f.UserID, f.HostID, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.SSHSession
	for rows.Next() {
		ss, err := scanSSHSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ss)
	}
	return out, rows.Err()
}

const recordingCols = `id, ssh_session_id, format, path, size_bytes, duration_ms, sha256, created_at`

func scanRecording(row pgx.Row) (*models.Recording, error) {
	var rec models.Recording
	err := row.Scan(&rec.ID, &rec.SSHSessionID, &rec.Format, &rec.Path, &rec.SizeBytes,
		&rec.DurationMS, &rec.SHA256, &rec.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &rec, nil
}

// RecordingInput carries fields to persist replay metadata for a session.
type RecordingInput struct {
	SSHSessionID uuid.UUID
	Format       string
	Path         string
	SizeBytes    int64
	DurationMS   int64
	SHA256       string
}

// CreateRecording stores replay metadata for an SSH session.
func (s *Store) CreateRecording(ctx context.Context, in RecordingInput) (*models.Recording, error) {
	if in.Format == "" {
		in.Format = "asciicast-v2"
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO session_recordings (ssh_session_id, format, path, size_bytes, duration_ms, sha256)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING `+recordingCols,
		in.SSHSessionID, in.Format, in.Path, in.SizeBytes, in.DurationMS, in.SHA256)
	return scanRecording(row)
}

// GetRecordingBySession returns the recording for an SSH session, if any.
func (s *Store) GetRecordingBySession(ctx context.Context, sshSessionID uuid.UUID) (*models.Recording, error) {
	return scanRecording(s.pool.QueryRow(ctx, `
		SELECT `+recordingCols+` FROM session_recordings
		WHERE ssh_session_id=$1 ORDER BY created_at DESC LIMIT 1`, sshSessionID))
}

// SFTPTransfer is a recorded file transfer over an SSH session.
type SFTPTransfer struct {
	ID           uuid.UUID  `json:"id"`
	SSHSessionID *uuid.UUID `json:"sshSessionId,omitempty"`
	UserID       *uuid.UUID `json:"userId,omitempty"`
	HostID       *uuid.UUID `json:"hostId,omitempty"`
	Direction    string     `json:"direction"`
	RemotePath   string     `json:"remotePath"`
	SizeBytes    int64      `json:"sizeBytes"`
	Status       string     `json:"status"`
	CreatedAt    time.Time  `json:"createdAt"`
	CompletedAt  *time.Time `json:"completedAt,omitempty"`
}

const sftpTransferCols = `id, ssh_session_id, user_id, host_id, direction, remote_path,
	size_bytes, status, created_at, completed_at`

func scanSFTPTransfer(row pgx.Row) (*SFTPTransfer, error) {
	var t SFTPTransfer
	err := row.Scan(&t.ID, &t.SSHSessionID, &t.UserID, &t.HostID, &t.Direction,
		&t.RemotePath, &t.SizeBytes, &t.Status, &t.CreatedAt, &t.CompletedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &t, nil
}

// SFTPTransferInput carries fields to record a file transfer.
type SFTPTransferInput struct {
	SSHSessionID *uuid.UUID
	UserID       *uuid.UUID
	HostID       *uuid.UUID
	Direction    string
	RemotePath   string
	SizeBytes    int64
	Status       string
}

// RecordSFTPTransfer persists an SFTP transfer record.
func (s *Store) RecordSFTPTransfer(ctx context.Context, in SFTPTransferInput) (*SFTPTransfer, error) {
	if in.Status == "" {
		in.Status = "started"
	}
	row := s.pool.QueryRow(ctx, `
		INSERT INTO sftp_transfers (ssh_session_id, user_id, host_id, direction, remote_path, size_bytes, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING `+sftpTransferCols,
		in.SSHSessionID, in.UserID, in.HostID, in.Direction, in.RemotePath, in.SizeBytes, in.Status)
	return scanSFTPTransfer(row)
}

// SFTPTransferFilter narrows a transfer list query.
type SFTPTransferFilter struct {
	SSHSessionID *uuid.UUID
	UserID       *uuid.UUID
	HostID       *uuid.UUID
	Limit        int
	Offset       int
}

// ListSFTPTransfers returns SFTP transfers matching the filter, newest first.
func (s *Store) ListSFTPTransfers(ctx context.Context, f SFTPTransferFilter) ([]SFTPTransfer, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+sftpTransferCols+`
		FROM sftp_transfers
		WHERE ($1::uuid IS NULL OR ssh_session_id=$1)
		  AND ($2::uuid IS NULL OR user_id=$2)
		  AND ($3::uuid IS NULL OR host_id=$3)
		ORDER BY created_at DESC LIMIT $4 OFFSET $5`,
		f.SSHSessionID, f.UserID, f.HostID, f.Limit, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SFTPTransfer
	for rows.Next() {
		t, err := scanSFTPTransfer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}
