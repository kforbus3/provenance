package dbbroker

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"

	mysqldriver "github.com/go-sql-driver/mysql"
	mssql "github.com/microsoft/go-mssqldb"

	"github.com/fleet-terminal/backend/internal/models"
)

// tunnelDialer hands a single pre-established SSH-tunnel connection to a database/sql
// driver exactly once. The broker opens one tunnel per query, so the pool is capped at
// one connection and the driver dials once; a second dial (unexpected) fails rather
// than opening an un-tunneled socket. closeIfUnused releases the tunnel if the driver
// never consumed it (e.g. a connect error before dialing).
type tunnelDialer struct {
	mu       sync.Mutex
	conn     net.Conn
	consumed bool
}

func (d *tunnelDialer) get() (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.consumed {
		return nil, fmt.Errorf("tunnel already consumed")
	}
	d.consumed = true
	return d.conn, nil
}

func (d *tunnelDialer) closeIfUnused() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.consumed && d.conn != nil {
		_ = d.conn.Close()
	}
}

// DialContext satisfies go-mssqldb's Dialer interface.
func (d *tunnelDialer) DialContext(_ context.Context, _, _ string) (net.Conn, error) {
	return d.get()
}

// mysqlDialSeq makes each MySQL registered-dialer name unique so concurrent queries
// never share (or overwrite) a global registration.
var mysqlDialSeq atomic.Uint64

// executeMySQL runs the statement over the tunnel using the MySQL wire protocol
// (also covers MariaDB). The go-sql-driver dialer is registered under a unique network
// name bound to this call's tunnel, then deregistered.
func executeMySQL(cctx context.Context, tunnel net.Conn, sessionID uuid.UUID, db *models.Database, dbUser, dbPass, statement string) (*QueryResult, error) {
	dialer := &tunnelDialer{conn: tunnel}
	defer dialer.closeIfUnused()

	netName := fmt.Sprintf("fleet-tunnel-%s-%d", sessionID.String(), mysqlDialSeq.Add(1))
	mysqldriver.RegisterDialContext(netName, func(_ context.Context, _ string) (net.Conn, error) {
		return dialer.get()
	})
	defer mysqldriver.DeregisterDialContext(netName)

	cfg := mysqldriver.NewConfig()
	cfg.User = dbUser
	cfg.Passwd = dbPass
	cfg.Net = netName
	cfg.Addr = db.Address // passed to the dialer, which ignores it (tunnel is fixed)
	cfg.DBName = db.DatabaseName
	cfg.AllowNativePasswords = true

	connector, err := mysqldriver.NewConnector(cfg)
	if err != nil {
		return nil, err
	}
	sqlDB := sql.OpenDB(connector)
	sqlDB.SetMaxOpenConns(1)
	defer sqlDB.Close()
	return runSQLDB(cctx, sqlDB, statement)
}

// executeSQLServer runs the statement over the tunnel using the TDS protocol.
func executeSQLServer(cctx context.Context, tunnel net.Conn, db *models.Database, dbUser, dbPass, statement string) (*QueryResult, error) {
	dialer := &tunnelDialer{conn: tunnel}
	defer dialer.closeIfUnused()

	// encrypt=disable: the SSH tunnel already provides transport security, and the
	// target may not present a TLS cert. database is optional (defaults to the login's).
	dsn := fmt.Sprintf("sqlserver://%s:%s@%s:%d?database=%s&encrypt=disable",
		url.QueryEscape(dbUser), url.QueryEscape(dbPass), db.Address, db.Port, url.QueryEscape(db.DatabaseName))
	connector, err := mssql.NewConnector(dsn)
	if err != nil {
		return nil, err
	}
	connector.Dialer = dialer
	sqlDB := sql.OpenDB(connector)
	sqlDB.SetMaxOpenConns(1)
	defer sqlDB.Close()
	return runSQLDB(cctx, sqlDB, statement)
}

// runSQLDB executes one statement against a database/sql handle and shapes the result.
// SELECT-shaped statements return a row grid; others report rows affected. The split is
// by leading keyword because database/sql needs Query vs Exec chosen up front, and
// calling the wrong one either discards rows or errors on some drivers.
func runSQLDB(cctx context.Context, sqlDB *sql.DB, statement string) (*QueryResult, error) {
	if isRowReturning(statement) {
		rows, err := sqlDB.QueryContext(cctx, statement)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		return scanSQLRows(rows)
	}
	r, err := sqlDB.ExecContext(cctx, statement)
	if err != nil {
		return nil, err
	}
	res := &QueryResult{Columns: []string{}, Rows: [][]string{}}
	if n, aerr := r.RowsAffected(); aerr == nil {
		res.Command = fmt.Sprintf("OK, %d row(s) affected", n)
	} else {
		res.Command = "OK"
	}
	return res, nil
}

// isRowReturning reports whether a statement's leading keyword yields a result set.
func isRowReturning(statement string) bool {
	s := strings.ToLower(strings.TrimLeft(statement, " \t\r\n("))
	for _, kw := range []string{"select", "show", "with", "explain", "describe", "desc ", "pragma", "values", "table "} {
		if strings.HasPrefix(s, kw) {
			return true
		}
	}
	return false
}

// scanSQLRows drains a *sql.Rows into a row-capped QueryResult, stringifying each cell.
func scanSQLRows(rows *sql.Rows) (*QueryResult, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	res := &QueryResult{Columns: cols, Rows: [][]string{}}
	for rows.Next() {
		if len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		cells := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make([]string, len(cols))
		for i, v := range cells {
			row[i] = stringify(v)
		}
		res.Rows = append(res.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	res.RowCount = len(res.Rows)
	if res.Command == "" {
		res.Command = fmt.Sprintf("%d row(s)", res.RowCount)
	}
	return res, nil
}
