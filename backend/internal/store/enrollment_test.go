package store

import (
	"context"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestNextFreeWGCandidate exercises the pure overlay-address allocation policy: the
// legacy /24 fallback keeps working, a supplied subnet is honored, a larger mask
// lifts the host ceiling past the old .10–.250 / single-/24 window, and the jump
// address and already-used addresses are skipped.
func TestNextFreeWGCandidate(t *testing.T) {
	cases := []struct {
		name    string
		jump    string
		subnet  string
		used    []string
		want    string
		wantErr bool
	}{
		{
			name: "legacy no subnet starts at .10",
			jump: "10.100.0.1", subnet: "",
			want: "10.100.0.10",
		},
		{
			name: "24 subnet keeps working and skips jump",
			jump: "10.100.0.1", subnet: "10.100.0.0/24",
			want: "10.100.0.2", // .0 network, .1 jump both skipped
		},
		{
			name: "24 subnet skips used",
			jump: "10.100.0.1", subnet: "10.100.0.0/24",
			used: []string{"10.100.0.2", "10.100.0.3"},
			want: "10.100.0.4",
		},
		{
			name: "16 subnet lifts the ceiling past a full /24",
			jump: "10.100.0.1", subnet: "10.100.0.0/16",
			// Fill the entire first /24 so allocation must cross into the next one,
			// which the old hard-coded /24 loop could never do.
			used: fill24("10.100.0."),
			want: "10.100.1.0",
		},
		{
			name: "exhausted small block errors",
			jump: "10.100.0.1", subnet: "10.100.0.0/30", // usable hosts: .1 (jump), .2
			used:    []string{"10.100.0.2"},
			wantErr: true,
		},
		{
			name: "invalid subnet errors", jump: "10.100.0.1", subnet: "not-a-cidr", wantErr: true,
		},
		{
			name: "invalid jump in legacy path errors", jump: "nope", subnet: "", wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			used := map[string]bool{}
			for _, u := range c.used {
				used[u] = true
			}
			got, err := nextFreeWGCandidate(c.jump, c.subnet, used)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func fill24(prefix string) []string {
	out := make([]string, 0, 256)
	for n := 0; n <= 255; n++ {
		out = append(out, prefix+itoa(n))
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestReserveWGAddressConcurrent proves the race-safety guarantee against a real
// Postgres: many goroutines (standing in for concurrent backend replicas) reserve
// overlay addresses at once and every one is distinct — no double-assignment. Gated
// on FLEET_STORE_TEST_DB (a DSN to a throwaway Postgres migrated with the hosts
// table and the 0075 unique index).
func TestReserveWGAddressConcurrent(t *testing.T) {
	dsn := os.Getenv("FLEET_STORE_TEST_DB")
	if dsn == "" {
		t.Skip("set FLEET_STORE_TEST_DB to a Postgres DSN with the hosts schema")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	st := New(pool)

	const n = 50
	// Create n hosts with no overlay address yet.
	ids := make([]uuid.UUID, n)
	for i := range ids {
		h, err := st.CreateHost(ctx, HostInput{Hostname: "race-" + itoa(i)})
		if err != nil {
			t.Fatalf("create host: %v", err)
		}
		ids[i] = h.ID
	}
	t.Cleanup(func() {
		for _, id := range ids {
			_ = st.DeleteHost(ctx, id)
		}
	})

	var wg sync.WaitGroup
	var mu sync.Mutex
	seen := map[string]uuid.UUID{}
	errs := make(chan error, n)
	for _, id := range ids {
		wg.Add(1)
		go func(id uuid.UUID) {
			defer wg.Done()
			addr, err := st.ReserveWGAddress(ctx, id, "10.100.0.1", "10.100.0.0/16")
			if err != nil {
				errs <- err
				return
			}
			mu.Lock()
			if other, dup := seen[addr]; dup {
				errs <- &dupErr{addr: addr, a: other, b: id}
			}
			seen[addr] = id
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent allocation collided or failed: %v", e)
	}
	if len(seen) != n {
		t.Fatalf("expected %d distinct addresses, got %d", n, len(seen))
	}
}

type dupErr struct {
	addr string
	a, b uuid.UUID
}

func (e *dupErr) Error() string {
	return "address " + e.addr + " assigned to both " + e.a.String() + " and " + e.b.String()
}
