package ws

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestBackplaneCrossInstance proves the Postgres LISTEN/NOTIFY bridge end-to-end for
// every cross-instance message class: a normal event (fans to a peer's hub clients),
// a terminate control, and the live-shadow subscribe + (chunked) frame relay. Two
// real Backplane instances share one database; A publishes, B must receive.
//
// Requires a real Postgres — set FLEET_TEST_DB to its DSN; skipped otherwise.
func TestBackplaneCrossInstance(t *testing.T) {
	dsn := os.Getenv("FLEET_TEST_DB")
	if dsn == "" {
		t.Skip("set FLEET_TEST_DB to a Postgres DSN to run the backplane integration test")
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatalf("connect: %v", err)
	}
	// Cancel first so the Run goroutines release their LISTEN connections, THEN close
	// the pool — otherwise pool.Close() blocks on the still-listening connections.
	t.Cleanup(func() {
		cancel()
		time.Sleep(200 * time.Millisecond)
		pool.Close()
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// B is the receiver: a hub with one test client, plus captured handlers.
	hubB := NewHub()
	clientB := &client{send: make(chan []byte, 8), userID: uuid.New()}
	hubB.clients[clientB] = struct{}{}

	termCh := make(chan string, 4)
	ctlCh := make(chan string, 4)
	frameCh := make(chan []byte, 64)

	bpA := NewBackplane(pool, "instance-A", NewHub(), log)
	bpB := NewBackplane(pool, "instance-B", hubB, log)
	bpB.SetControlHandler(func(action, target string) {
		if action == controlTerminate {
			termCh <- target
		}
	})
	bpB.SetShadowHandlers(
		func(action string, sid uuid.UUID, origin string) { ctlCh <- action + "|" + origin },
		func(sid uuid.UUID, kind string, data []byte, cols, rows int) {
			b := make([]byte, len(data))
			copy(b, data)
			frameCh <- b
		},
	)
	go bpA.Run(ctx)                    // drives A's async shadow drain
	go bpB.Run(ctx)                    // listens + dispatches
	time.Sleep(700 * time.Millisecond) // let both LISTEN connections establish

	sid := uuid.New()

	// 1) Event → reaches B's hub client.
	bpA.publish(envelope{Type: "host.status", Data: toRaw(map[string]any{"status": "online"})})
	select {
	case <-clientB.send:
	case <-time.After(3 * time.Second):
		t.Fatal("cross-instance EVENT not delivered to peer hub client")
	}

	// 2) Terminate control → reaches B's control handler with the right target.
	bpA.publish(envelope{Control: controlTerminate, Target: sid.String()})
	select {
	case got := <-termCh:
		if got != sid.String() {
			t.Fatalf("terminate target mismatch: %s != %s", got, sid)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cross-instance TERMINATE not delivered")
	}

	// 3) Shadow subscribe → reaches B's shadow control handler, tagged with A's origin.
	bpA.PublishShadowSub(sid, true)
	select {
	case got := <-ctlCh:
		if got != controlShadowSub+"|instance-A" {
			t.Fatalf("shadow-sub mismatch: %q", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cross-instance SHADOW SUBSCRIBE not delivered")
	}

	// 4) Shadow frame larger than the chunk cap → arrives as multiple frames whose
	//    bytes reassemble to the original (chunking + reassembly across NOTIFY).
	payload := bytes.Repeat([]byte("Z"), 10000) // > 2 * shadowChunk
	bpA.PublishShadowFrame(sid, "o", payload, 0, 0)
	var got []byte
	deadline := time.After(4 * time.Second)
	for len(got) < len(payload) {
		select {
		case chunk := <-frameCh:
			got = append(got, chunk...)
		case <-deadline:
			t.Fatalf("cross-instance SHADOW FRAME incomplete: got %d of %d bytes", len(got), len(payload))
		}
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("reassembled shadow frame does not match the original output")
	}
}
