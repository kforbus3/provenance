package store

import (
	"context"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// queryCounter is a pgx tracer that counts every query the pool issues, so a test
// can assert the ListHosts fan-out is bounded (constant) rather than O(N) per host.
type queryCounter struct{ n int64 }

func (q *queryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	atomic.AddInt64(&q.n, 1)
	return ctx
}
func (q *queryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// TestListHostsQueryCountConstant proves the N+1 is gone: listing 3 hosts and
// listing 30 hosts must issue the SAME number of queries (1 page query + 4 batched
// detail queries), not a per-host multiple. Gated on FLEET_STORE_TEST_DB.
func TestListHostsQueryCountConstant(t *testing.T) {
	dsn := os.Getenv("FLEET_STORE_TEST_DB")
	if dsn == "" {
		t.Skip("set FLEET_STORE_TEST_DB to a Postgres DSN with the hosts schema")
	}
	ctx := context.Background()

	count := func(nHosts int) int64 {
		cfg, err := pgxpool.ParseConfig(dsn)
		if err != nil {
			t.Fatalf("parse dsn: %v", err)
		}
		qc := &queryCounter{}
		cfg.ConnConfig.Tracer = qc
		pool, err := pgxpool.NewWithConfig(ctx, cfg)
		if err != nil {
			t.Fatalf("connect: %v", err)
		}
		defer pool.Close()
		st := New(pool)

		var ids []string
		for i := 0; i < nHosts; i++ {
			h, err := st.CreateHost(ctx, HostInput{Hostname: "qc-" + itoa(nHosts) + "-" + itoa(i)})
			if err != nil {
				t.Fatalf("create host: %v", err)
			}
			ids = append(ids, h.ID.String())
		}
		t.Cleanup(func() {
			for _, id := range ids {
				_, _ = pool.Exec(ctx, `DELETE FROM hosts WHERE id=$1`, id)
			}
		})

		atomic.StoreInt64(&qc.n, 0)
		hosts, err := st.ListHosts(ctx, 1000, 0)
		if err != nil {
			t.Fatalf("list hosts: %v", err)
		}
		if len(hosts) < nHosts {
			t.Fatalf("expected at least %d hosts, got %d", nHosts, len(hosts))
		}
		return atomic.LoadInt64(&qc.n)
	}

	small := count(3)
	large := count(30)
	if small != large {
		t.Fatalf("ListHosts query count grew with fleet size: %d for 3 hosts, %d for 30 (N+1 not eliminated)", small, large)
	}
	t.Logf("ListHosts issued %d queries regardless of fleet size", small)
}
