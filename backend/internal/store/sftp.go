package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CompleteSFTPTransfer finalizes a transfer record with its byte count + status.
func (s *Store) CompleteSFTPTransfer(ctx context.Context, id uuid.UUID, sizeBytes int64, status string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sftp_transfers SET size_bytes=$2, status=$3, completed_at=now() WHERE id=$1`,
		id, sizeBytes, status)
	return err
}

// FailStaleSFTPTransfers gives a terminal status to transfers abandoned by a
// session that is over.
//
// Every other kind of in-flight work is reconciled at startup -- scans, vulnerability
// scans, remediations, playbook runs, command runs, script runs, enrollment jobs --
// and file transfers were not. Two uploads from June sat at "started" for three
// months: a transfer interrupted by a restart never got a status, so it reads as
// in-flight forever, in the UI and in every report built from these rows.
//
// A transfer has no instance of its own; its SSH session does. So a transfer is
// abandoned when its session has ended, when its session's owning instance is dead,
// or when the session row is gone entirely (pruned by retention long after the
// transfer stopped). A live peer's in-flight transfer is left strictly alone.
func (s *Store) FailStaleSFTPTransfers(ctx context.Context, lease time.Duration, self uuid.UUID) (int64, error) {
	tag, err := s.pool.Exec(ctx, `
		UPDATE sftp_transfers t SET status='interrupted', completed_at=now()
		WHERE t.completed_at IS NULL AND (
		  NOT EXISTS (SELECT 1 FROM ssh_sessions s WHERE s.id = t.ssh_session_id)
		  OR EXISTS (SELECT 1 FROM ssh_sessions s WHERE s.id = t.ssh_session_id
		             AND (s.ended_at IS NOT NULL OR `+deadOwnerPredicate("s")+`)))`,
		lease.String(), self)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
