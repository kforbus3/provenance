package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kforbus3/provenance/backend/internal/db"
)

// A container update rollout rewrote a stack's image tag and saved it without a
// verify command, because it had no reason to know one -- and the save wrote ""
// over the command the operator had set. The stack's first automated update
// switched its verification off, silently, for every update after it.
//
// Leaving the command out must keep it; only an explicit empty string clears it.
func TestSavingAStackWithoutAVerifyCommandKeepsTheStoredOne(t *testing.T) {
	url := os.Getenv("PROV_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("no test database offered; run via `make test-db`")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	s := &Store{pool: pool}
	h, err := s.CreateHost(ctx, HostInput{Hostname: "stackverify-" + uuid.NewString()[:8]})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}

	cmd := "curl -fsS http://localhost:8080/health"
	in := StackInput{HostID: h.ID, Name: "voice", Path: "/opt/stacks/voice",
		Compose:       "services:\n  llm:\n    image: ghcr.io/ggml-org/llama.cpp:server-cuda-b1\n",
		VerifyCommand: &cmd, AuthorName: "operator"}
	if _, err := s.UpsertStack(ctx, in); err != nil {
		t.Fatalf("operator save: %v", err)
	}

	// What a rollout writes: the same stack, a new tag, no verify command.
	st, err := s.UpsertStack(ctx, StackInput{HostID: h.ID, Name: "voice", Path: "/opt/stacks/voice",
		Compose: "services:\n  llm:\n    image: ghcr.io/ggml-org/llama.cpp:server-cuda-b2\n",
		Note:    "rollout", AuthorName: "container update rollout"})
	if err != nil {
		t.Fatalf("rollout save: %v", err)
	}
	if st.Revision != 2 {
		t.Fatalf("the tag change must be a new revision, got %d", st.Revision)
	}
	if st.VerifyCommand != cmd {
		t.Fatalf("a save that did not mention the verify command erased it: got %q, want %q",
			st.VerifyCommand, cmd)
	}

	// A path-only correction, the other automated save, keeps it too.
	st, err = s.UpsertStack(ctx, StackInput{HostID: h.ID, Name: "voice", Path: "/srv/voice",
		Compose: st.Compose, AuthorName: "container update rollout"})
	if err != nil {
		t.Fatalf("path save: %v", err)
	}
	if st.VerifyCommand != cmd {
		t.Fatalf("a path correction erased the verify command: got %q", st.VerifyCommand)
	}

	// The editor clearing the field is still a real choice and still works.
	empty := ""
	st, err = s.UpsertStack(ctx, StackInput{HostID: h.ID, Name: "voice", Path: st.Path,
		Compose: st.Compose, VerifyCommand: &empty, AuthorName: "operator"})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if st.VerifyCommand != "" {
		t.Fatalf("an explicit empty verify command must clear it, got %q", st.VerifyCommand)
	}
}
