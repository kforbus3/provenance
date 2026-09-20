package backup

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Restoring into the live database is not safe, and the reason is not obvious.
//
// pg_dump writes `DROP ... IF EXISTS` for everything it contains and nothing for what
// it does not. Applied to a database that has moved ON from the backup — which is
// exactly a failed upgrade, where the migrations ran before the failure — those DROPs
// hit objects that later migrations have since made things depend on:
//
//	ERROR: cannot drop constraint vuln_scans_pkey on table public.vuln_scans
//	       because other objects depend on it
//
// The restore then stops part-way with ON_ERROR_STOP, leaving a database holding rows
// from BOTH sides and a schema_migrations that describes neither. Measured: restoring a
// 66-migration backup over a database migrated to 109 failed, and afterwards the table
// held the pre-upgrade row and the post-upgrade one together.
//
// That is the one scenario the pre-upgrade backup exists for. So a restore does not
// touch the live database at all until it has succeeded somewhere else: it builds a NEW
// database, restores into that, and only then swaps the two by rename, keeping the
// previous one. Nothing is lost if the restore fails, because nothing was dropped.
//
// Restoring is still not an operation the running application can perform on itself.
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
	Name    string
	Target  string
	Applied int64 // bytes of SQL fed to psql
	// Into is the database the dump was actually loaded into, and Superseded is where
	// the previous one was put. Both are named so an operator can find them: a restore
	// that swapped databases has left the old one on disk, and that is the undo.
	Into       string
	Superseded string
	Warnings   []string
	Took       time.Duration
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

	// Where the dump will actually be loaded. A fresh database beside the target, so a
	// failure leaves the live one untouched; see the file comment.
	base, dbName, err := splitDSN(target)
	if err != nil {
		return nil, err
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	restoreInto := dbName + "_restore_" + stamp
	superseded := dbName + "_superseded_" + stamp

	admin, aerr := pgxpool.New(ctx, base+"/postgres"+dsnQuery(target))
	if aerr != nil {
		return nil, fmt.Errorf("connect to the maintenance database to build a restore target: %w", aerr)
	}
	defer admin.Close()
	if _, err := admin.Exec(ctx, `CREATE DATABASE "`+restoreInto+`"`); err != nil {
		return nil, fmt.Errorf("create the restore database %s: %w", restoreInto, err)
	}
	// From here, anything that goes wrong must leave the live database alone. The
	// half-built copy is dropped rather than left to confuse the next attempt.
	cleanup := func() {
		dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer dcancel()
		_, _ = admin.Exec(dctx, `DROP DATABASE IF EXISTS "`+restoreInto+`"`)
	}
	target = base + "/" + restoreInto + dsnQuery(target)

	path, err := s.Path(name)
	if err != nil {
		cleanup()
		return nil, err
	}
	pass := s.passphrase()
	if pass == "" {
		cleanup()
		return nil, errors.New("no backup passphrase configured, so this backup cannot be read")
	}
	env, err := pgEnv(target)
	if err != nil {
		cleanup()
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
		cleanup()
		return nil, err
	}
	counted := &countingReader{r: pipe}
	psql.Stdin = counted
	var psqlErr, decErr strings.Builder
	psql.Stderr = &psqlErr
	dec.Stderr = &decErr

	if err := psql.Start(); err != nil {
		cleanup()
		return nil, err
	}
	if err := dec.Start(); err != nil {
		cleanup()
		return nil, err
	}
	// The CONSUMER first, then the producer — the order matters and the failure it
	// causes looks like a corrupt backup.
	//
	// cmd.Wait() closes the pipe it handed out. psql's stdin here is a counting reader
	// rather than the *os.File itself, so exec runs its own goroutine copying between
	// them; waiting on openssl first closes the pipe under that goroutine and psql
	// receives a truncated stream:
	//
	//	psql:<stdin>:6837: ERROR: syntax error at end of input
	//
	// which reads exactly like a damaged dump and is nothing of the kind.
	psqlWait := psql.Wait()
	decWait := dec.Wait()
	if psqlWait != nil {
		cleanup()
		// The live database was never touched, and saying so is most of what an
		// operator needs at this moment.
		detail := strings.TrimSpace(psqlErr.String())
		// One cause is worth naming, because the message PostgreSQL gives for it says
		// nothing about versions: a dump written by a NEWER pg_dump than the server
		// being restored to carries settings that server has never heard of.
		if strings.Contains(detail, "unrecognized configuration parameter") {
			detail += "\n\nThis usually means the backup was written by a NEWER pg_dump than " +
				"the PostgreSQL being restored to — the dump sets parameters this server " +
				"does not have. Compare `pg_dump --version` where the backup was taken " +
				"with the server's own version; the shipped stack keeps them matched, so " +
				"this normally means one side was upgraded on its own."
		}
		return nil, fmt.Errorf("the backup could not be loaded: %v\n%s\n"+
			"Nothing was changed — the restore was building a separate database and it "+
			"has been removed. The database in service is exactly as it was",
			psqlWait, detail)
	}
	if decWait != nil {
		cleanup()
		return nil, fmt.Errorf("decryption failed partway: %v %s (nothing was changed)",
			decWait, strings.TrimSpace(decErr.String()))
	}

	// Loaded. Only now does anything happen to the database in service: the two are
	// swapped by rename, which is atomic per database and leaves the previous one on
	// disk under a name that says what it is. That is the undo.
	if _, err := admin.Exec(ctx, `ALTER DATABASE "`+dbName+`" RENAME TO "`+superseded+`"`); err != nil {
		cleanup()
		return nil, fmt.Errorf("the backup loaded cleanly into %s, but the live database "+
			"could not be renamed out of the way: %w. Nothing was changed; the loaded copy "+
			"has been removed", restoreInto, err)
	}
	if _, err := admin.Exec(ctx, `ALTER DATABASE "`+restoreInto+`" RENAME TO "`+dbName+`"`); err != nil {
		// Put the original back rather than leaving the deployment with no database at
		// the name it serves from.
		_, _ = admin.Exec(ctx, `ALTER DATABASE "`+superseded+`" RENAME TO "`+dbName+`"`)
		cleanup()
		return nil, fmt.Errorf("could not put the restored copy in place: %w. The original "+
			"database has been returned to %s and nothing was lost", err, dbName)
	}

	res := &RestoreResult{
		Name: name, Target: redactDSN(target), Applied: counted.n,
		Into: dbName, Superseded: superseded, Took: time.Since(started),
	}
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

// splitDSN separates a postgres URL into everything before the database name and the
// database name itself, so a sibling database on the same server can be addressed.
func splitDSN(dsn string) (base, db string, err error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return "", "", fmt.Errorf("parse database url: %w", err)
	}
	db = strings.TrimPrefix(u.Path, "/")
	if db == "" {
		return "", "", fmt.Errorf("database url names no database")
	}
	u.Path = ""
	u.RawQuery = ""
	return strings.TrimSuffix(u.String(), "/"), db, nil
}

// dsnQuery is the original URL's query string, kept so sslmode and friends survive
// being pointed at a different database on the same server.
func dsnQuery(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}
