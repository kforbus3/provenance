package backup

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Restoring is not an operation the running application can perform on itself.
//
// The dump is written with --clean --if-exists, so applying it DROPs and recreates
// every object in the database the backend is currently serving from. Half its
// requests would hit tables that no longer exist, its connection pool would be holding
// handles to a schema being rebuilt underneath it, and whether it survived would
// depend on what happened to be in flight. That is why this is a provctl command run
// against a stopped stack rather than a button in a UI that is about to be deleted.
//
// The guard is a positive assertion, not a warning: it counts the OTHER connections to
// the target database and refuses while any exist. An operator who has genuinely
// stopped the application passes that check without knowing it is there; one who has
// not gets told which is the problem, instead of a half-restored database.

// RestoreOptions are the decisions a restore needs from the operator.
type RestoreOptions struct {
	// Target overrides the database URL to restore INTO. Empty means the configured
	// backup/owner DSN — restoring in place. Set it to rehearse into a scratch
	// database, which is the only way to find out a backup is good before needing it.
	Target string
	// Force skips the "nothing else is connected" check. It exists because a
	// deployment can have a stray connection nobody can find, and refusing forever is
	// its own kind of failure — but it is never the default.
	Force bool
}

// RestoreResult is what a restore did.
type RestoreResult struct {
	Name     string
	Target   string
	Applied  int64 // bytes of SQL fed to psql
	Warnings []string
	Took     time.Duration
}

// Restore applies a stored backup to a database.
func (s *Service) Restore(ctx context.Context, name string, opt RestoreOptions) (*RestoreResult, error) {
	// Read it before trusting it. A restore is the one operation where discovering
	// the file is truncated AFTER dropping every table is unrecoverable.
	v, err := s.Verify(ctx, name)
	if err != nil {
		return nil, err
	}
	if !v.OK() {
		return nil, fmt.Errorf("refusing to restore %s: %s", name, v.Problem())
	}

	target := strings.TrimSpace(opt.Target)
	if target == "" {
		target = s.dumpDSN()
	}
	if _, err := exec.LookPath("psql"); err != nil {
		return nil, errors.New("psql not available")
	}
	if !opt.Force {
		n, who, err := otherConnections(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("checking what is connected to the target database: %w", err)
		}
		if n > 0 {
			return nil, fmt.Errorf("%d other connection(s) are using the target database (%s). "+
				"A restore DROPs and recreates every table, so the application must be stopped "+
				"first — `docker compose stop backend` — or pass --force if you know what those "+
				"connections are", n, strings.Join(who, ", "))
		}
	}

	path, err := s.Path(name)
	if err != nil {
		return nil, err
	}
	pass := s.passphrase()
	if pass == "" {
		return nil, errors.New("no backup passphrase configured, so this backup cannot be read")
	}
	env, err := pgEnv(target)
	if err != nil {
		return nil, err
	}

	started := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 60*time.Minute)
	defer cancel()

	dec := exec.CommandContext(cctx, "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
		"-pass", "env:PROV_BK_PASS", "-in", path)
	dec.Env = append(os.Environ(), "PROV_BK_PASS="+pass)
	// ON_ERROR_STOP so a failure partway is a failure, not a database restored up to
	// the point something went wrong and reported as success.
	psql := exec.CommandContext(cctx, "psql", "--quiet", "--no-psqlrc",
		"-v", "ON_ERROR_STOP=1", "-f", "-")
	psql.Env = append(os.Environ(), env...)
	pipe, err := dec.StdoutPipe()
	if err != nil {
		return nil, err
	}
	counted := &countingReader{r: pipe}
	psql.Stdin = counted
	var psqlErr, decErr strings.Builder
	psql.Stderr = &psqlErr
	dec.Stderr = &decErr

	if err := psql.Start(); err != nil {
		return nil, err
	}
	if err := dec.Start(); err != nil {
		return nil, err
	}
	decWait := dec.Wait()
	psqlWait := psql.Wait()
	if psqlWait != nil {
		return nil, fmt.Errorf("restore failed and the database is part-way through a "+
			"rebuild — it must not be served until this is resolved: %v\n%s",
			psqlWait, strings.TrimSpace(psqlErr.String()))
	}
	if decWait != nil {
		return nil, fmt.Errorf("decryption failed partway: %v %s", decWait, strings.TrimSpace(decErr.String()))
	}

	res := &RestoreResult{Name: name, Target: redactDSN(target), Applied: counted.n, Took: time.Since(started)}
	for _, line := range strings.Split(psqlErr.String(), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			res.Warnings = append(res.Warnings, line)
		}
	}
	return res, nil
}

// otherConnections counts backends attached to the target database besides this one.
func otherConnections(ctx context.Context, dsn string) (int, []string, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return 0, nil, err
	}
	defer pool.Close()
	rows, err := pool.Query(ctx, `
		SELECT DISTINCT coalesce(application_name, '') , usename
		FROM pg_stat_activity
		WHERE datname = current_database() AND pid <> pg_backend_pid()`)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	var who []string
	for rows.Next() {
		var app, user string
		if err := rows.Scan(&app, &user); err != nil {
			continue
		}
		label := user
		if app != "" {
			label += " (" + app + ")"
		}
		who = append(who, label)
	}
	return len(who), who, rows.Err()
}

// countingReader counts what actually reached psql, so a restore can report how much
// SQL it applied rather than how large the file was.
type countingReader struct {
	r interface{ Read([]byte) (int, error) }
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// redactDSN renders a connection string without its password, for printing.
func redactDSN(dsn string) string {
	at := strings.LastIndex(dsn, "@")
	sep := strings.Index(dsn, "://")
	if at < 0 || sep < 0 || at < sep {
		return dsn
	}
	creds := dsn[sep+3 : at]
	if i := strings.Index(creds, ":"); i >= 0 {
		creds = creds[:i] + ":***"
	}
	return dsn[:sep+3] + creds + dsn[at:]
}
