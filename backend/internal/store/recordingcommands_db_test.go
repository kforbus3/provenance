package store

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Deleting a recording left everything typed in it searchable.
//
// session_commands are a recording's keystrokes copied into plaintext rows, and they
// cascaded only from ssh_sessions. Recording deletion and recording retention removed
// the encrypted file and kept the commands; in production the Commands tab still
// returned commands three months after their recordings were pruned, each with a
// Replay button that could only say "No recording is available for this session".
//
// Each case keeps a second, untouched session alongside, so a fix that deleted
// commands too broadly would fail here as well.

func recordedSession(t *testing.T, ctx context.Context, s *Store, cmds ...string) (sessionID, recordingID uuid.UUID) {
	t.Helper()
	sess, err := s.CreateSSHSession(ctx, SSHSessionInput{Username: "keith", Hostname: "ai"})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.CreateRecording(ctx, RecordingInput{SSHSessionID: sess.ID, Path: sess.ID.String() + ".cast"})
	if err != nil {
		t.Fatal(err)
	}
	in := make([]SessionCommandInput, 0, len(cmds))
	for i, c := range cmds {
		in = append(in, SessionCommandInput{Text: c, Offset: float64(i)})
	}
	if err := s.IndexRecordingCommands(ctx, rec.ID, sess.ID, in); err != nil {
		t.Fatal(err)
	}
	return sess.ID, rec.ID
}

func commandCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, sessionID uuid.UUID) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM session_commands WHERE ssh_session_id = $1`, sessionID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDeletingARecordingTakesItsCommands(t *testing.T) {
	ctx, s, pool := pruneTestStore(t)
	gone, _ := recordedSession(t, ctx, s, "sudo su", "echo secret > password.txt")
	kept, _ := recordedSession(t, ctx, s, "uptime")
	if commandCount(t, ctx, pool, gone) != 2 {
		t.Fatal("setup: the commands were not indexed")
	}

	if _, err := s.DeleteRecordingBySession(ctx, gone); err != nil {
		t.Fatal(err)
	}
	if n := commandCount(t, ctx, pool, gone); n != 0 {
		t.Fatalf("%d commands survive the deletion of their recording", n)
	}
	if n := commandCount(t, ctx, pool, kept); n != 1 {
		t.Fatalf("another session's commands were touched: %d left, want 1", n)
	}
	rows, err := s.SearchSessionCommands(ctx, uuid.Nil, true, "secret", "", 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("command search still finds %d commands from the deleted recording", len(rows))
	}
}

func TestPruningARecordingTakesItsCommands(t *testing.T) {
	ctx, s, pool := pruneTestStore(t)
	old, oldRec := recordedSession(t, ctx, s, "sudo su")
	fresh, _ := recordedSession(t, ctx, s, "uptime")
	if _, err := pool.Exec(ctx,
		`UPDATE session_recordings SET created_at = now() - interval '90 days' WHERE id = $1`, oldRec); err != nil {
		t.Fatal(err)
	}

	paths, _, err := s.PruneRecordingsBefore(ctx, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 {
		t.Fatalf("pruned %d recordings, want 1", len(paths))
	}
	if n := commandCount(t, ctx, pool, old); n != 0 {
		t.Fatalf("%d commands survive the prune of their recording", n)
	}
	if n := commandCount(t, ctx, pool, fresh); n != 1 {
		t.Fatalf("a recording inside retention lost its commands: %d left, want 1", n)
	}
}

// The indexer reads a recording outside the transaction that stores its commands, so
// the recording can be deleted in between. The commands must not be stored then.
func TestIndexingADeletedRecordingStoresNothing(t *testing.T) {
	ctx, s, pool := pruneTestStore(t)
	sess, err := s.CreateSSHSession(ctx, SSHSessionInput{Username: "keith", Hostname: "ai"})
	if err != nil {
		t.Fatal(err)
	}
	rec, err := s.CreateRecording(ctx, RecordingInput{SSHSessionID: sess.ID, Path: "x.cast"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteRecordingBySession(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.IndexRecordingCommands(ctx, rec.ID, sess.ID, []SessionCommandInput{{Text: "sudo su"}}); err != nil {
		t.Fatal(err)
	}
	if n := commandCount(t, ctx, pool, sess.ID); n != 0 {
		t.Fatalf("indexing a deleted recording stored %d commands", n)
	}
}
