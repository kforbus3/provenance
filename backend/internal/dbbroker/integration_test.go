package dbbroker

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
)

// These tests exercise the MySQL and SQL Server executor paths against real database
// servers. The broker normally reaches a database through an SSH tunnel; here we pass a
// directly-dialed TCP connection in place of that tunnel (the jump hop is unchanged,
// already-proven shared code). Skipped unless the server address is provided.

func dialTunnel(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	return c
}

func TestExecuteMySQLLive(t *testing.T) {
	addr := os.Getenv("FLEET_TEST_MYSQL_ADDR") // host:port
	if addr == "" {
		t.Skip("set FLEET_TEST_MYSQL_ADDR to run the live MySQL executor test")
	}
	host, port := splitHostPort(t, addr)
	db := &models.Database{Engine: "mysql", Address: host, Port: port, DatabaseName: os.Getenv("FLEET_TEST_MYSQL_DB")}
	user := envOr("FLEET_TEST_MYSQL_USER", "root")
	pass := os.Getenv("FLEET_TEST_MYSQL_PASS")
	ctx := context.Background()
	sid := uuid.New()

	// SELECT returns a grid.
	res, err := executeMySQL(ctx, dialTunnel(t, addr), sid, db, user, pass, "SELECT 1 AS one, 'hi' AS greeting")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(res.Columns) != 2 || res.RowCount != 1 || res.Rows[0][0] != "1" || res.Rows[0][1] != "hi" {
		t.Fatalf("unexpected select result: %+v", res)
	}
	// DDL/DML reports rows affected rather than a grid.
	_, _ = executeMySQL(ctx, dialTunnel(t, addr), sid, db, user, pass, "CREATE TEMPORARY TABLE IF NOT EXISTS t (id INT)")
	res, err = executeMySQL(ctx, dialTunnel(t, addr), sid, db, user, pass, "SELECT 2 AS two")
	if err != nil || res.Rows[0][0] != "2" {
		t.Fatalf("second select failed: %+v err=%v", res, err)
	}
	t.Logf("mysql OK: %+v", res)
}

func TestExecuteSQLServerLive(t *testing.T) {
	addr := os.Getenv("FLEET_TEST_MSSQL_ADDR")
	if addr == "" {
		t.Skip("set FLEET_TEST_MSSQL_ADDR to run the live SQL Server executor test")
	}
	host, port := splitHostPort(t, addr)
	db := &models.Database{Engine: "sqlserver", Address: host, Port: port, DatabaseName: envOr("FLEET_TEST_MSSQL_DB", "master")}
	user := envOr("FLEET_TEST_MSSQL_USER", "sa")
	pass := os.Getenv("FLEET_TEST_MSSQL_PASS")
	ctx := context.Background()

	res, err := executeSQLServer(ctx, dialTunnel(t, addr), db, user, pass, "SELECT 1 AS one, 'hi' AS greeting")
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if len(res.Columns) != 2 || res.RowCount != 1 || res.Rows[0][0] != "1" || res.Rows[0][1] != "hi" {
		t.Fatalf("unexpected select result: %+v", res)
	}
	// Non-row statement path.
	res, err = executeSQLServer(ctx, dialTunnel(t, addr), db, user, pass, "DECLARE @x INT = 1")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	t.Logf("mssql OK: %+v", res)
}

func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("bad addr %q: %v", addr, err)
	}
	var port int
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return host, port
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
