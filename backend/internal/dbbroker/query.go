package dbbroker

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fleet-terminal/backend/internal/auth"
	"github.com/fleet-terminal/backend/internal/httpx"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/secretbox"
)

const (
	maxSQLLen  = 100_000 // reject absurdly large statements
	maxRows    = 1000    // cap returned rows (result set), flag truncation
	queryLimit = 30 * time.Second
)

// QueryResult is one executed statement's outcome.
type QueryResult struct {
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	RowCount  int        `json:"rowCount"`
	Command   string     `json:"command"` // e.g. "SELECT 5", "UPDATE 2"
	Truncated bool       `json:"truncated"`
}

// query runs a single SQL statement against a registered database through the jump
// host, authenticated with the database's vaulted credential, and audits it. The
// operator never sees the credential.
func (h *handler) query(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		SQL string `json:"sql"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "invalid body")
		return
	}
	sql := strings.TrimSpace(body.SQL)
	if sql == "" {
		httpx.WriteError(w, http.StatusBadRequest, "sql is required")
		return
	}
	if len(sql) > maxSQLLen {
		httpx.WriteError(w, http.StatusBadRequest, "statement too large")
		return
	}
	db, err := h.d.Store.GetDatabase(r.Context(), id)
	if err != nil {
		httpx.WriteError(w, http.StatusNotFound, "database not found")
		return
	}
	if db.CredentialID == nil {
		httpx.WriteError(w, http.StatusBadRequest, "attach a vault credential to this database before connecting")
		return
	}
	dbUser, dbPass, err := h.credential(r.Context(), *db.CredentialID)
	if err != nil {
		httpx.WriteError(w, http.StatusBadGateway, "credential unavailable: "+err.Error())
		return
	}
	p := auth.MustPrincipal(r)

	res, qerr := h.execute(r.Context(), p.SessionID, db, dbUser, dbPass, sql)

	// Audit every attempt with the statement (truncated) — success or failure.
	rowCount := 0
	if res != nil {
		rowCount = res.RowCount
	}
	h.audit(r, "db.query", db.ID, map[string]any{
		"database": db.Name, "engine": db.Engine, "dbUser": dbUser,
		"sql": truncate(sql, 2000), "ok": qerr == nil, "rows": rowCount,
	})
	if qerr != nil {
		httpx.WriteError(w, http.StatusBadGateway, "query failed: "+qerr.Error())
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// credential resolves a vaulted password credential to (username, password). The
// plaintext is decrypted in RAM only, at point of use, and never returned to the client.
func (h *handler) credential(ctx context.Context, credID uuid.UUID) (user, pass string, err error) {
	sec, err := h.d.Store.GetVaultSecret(ctx, credID)
	if err != nil {
		return "", "", fmt.Errorf("credential not found")
	}
	if sec.Type != "password" {
		return "", "", fmt.Errorf("attached credential is not a password")
	}
	key, err := h.d.Cfg.VaultKey()
	if err != nil {
		return "", "", err
	}
	sealed, err := h.d.Store.GetVaultSecretSealed(ctx, credID)
	if err != nil {
		return "", "", err
	}
	pw, err := secretbox.Open(key, sealed)
	if err != nil {
		return "", "", fmt.Errorf("could not decrypt credential")
	}
	return sec.Username, string(pw), nil
}

// execute reaches the target database THROUGH the jump host (using the caller's
// session certificate for the jump hop and the vaulted credential for the database),
// runs the statement, and returns the (row-capped) result. The transport is a single
// SSH-tunneled TCP connection shared by every engine; the per-engine driver runs over
// it. Branch on db.Engine to add engines.
func (h *handler) execute(ctx context.Context, sessionID uuid.UUID, db *models.Database, dbUser, dbPass, sql string) (*QueryResult, error) {
	cctx, cancel := context.WithTimeout(ctx, queryLimit)
	defer cancel()

	tunnel, jumpClient, err := h.gw.DialRawViaJump(cctx, sessionID.String(), db.Address, db.Port)
	if err != nil {
		return nil, fmt.Errorf("reach database via jump host: %w", err)
	}
	defer func() {
		if jumpClient != nil {
			_ = jumpClient.Close()
		}
	}()

	switch normalizeEngine(db.Engine) {
	case "postgres":
		return executePostgres(cctx, tunnel, db, dbUser, dbPass, sql)
	case "mysql", "mariadb":
		return executeMySQL(cctx, tunnel, sessionID, db, dbUser, dbPass, sql)
	case "sqlserver":
		return executeSQLServer(cctx, tunnel, db, dbUser, dbPass, sql)
	default:
		_ = tunnel.Close()
		return nil, fmt.Errorf("unsupported engine %q", db.Engine)
	}
}

// executePostgres runs the statement over the tunnel using pgx.
func executePostgres(cctx context.Context, tunnel net.Conn, db *models.Database, dbUser, dbPass, sql string) (*QueryResult, error) {
	cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s sslmode=disable", db.Address, db.Port, db.DatabaseName))
	if err != nil {
		_ = tunnel.Close()
		return nil, err
	}
	cfg.User = dbUser
	cfg.Password = dbPass
	// The transport is the SSH tunnel we already opened; hand it to pgx once.
	used := false
	cfg.DialFunc = func(_ context.Context, _, _ string) (net.Conn, error) {
		if used {
			return nil, fmt.Errorf("tunnel already consumed")
		}
		used = true
		return tunnel, nil
	}

	conn, err := pgx.ConnectConfig(cctx, cfg)
	if err != nil {
		_ = tunnel.Close()
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Close(context.Background())

	rows, err := conn.Query(cctx, sql)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := &QueryResult{Rows: [][]string{}}
	for _, fd := range rows.FieldDescriptions() {
		res.Columns = append(res.Columns, string(fd.Name))
	}
	for rows.Next() {
		if len(res.Rows) >= maxRows {
			res.Truncated = true
			break
		}
		vals, verr := rows.Values()
		if verr != nil {
			return nil, verr
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			row[i] = stringify(v)
		}
		res.Rows = append(res.Rows, row)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, rerr
	}
	res.RowCount = len(res.Rows)
	res.Command = rows.CommandTag().String()
	return res, nil
}

// stringify renders a Postgres value cell for the JSON grid: NULL -> "", bytes/JSON
// as text, everything else via fmt.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	case time.Time:
		return t.Format(time.RFC3339)
	default:
		return fmt.Sprint(v)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
