// Package backup creates encrypted logical database backups (pg_dump piped
// through openssl AES-256-CBC/PBKDF2) to a destination directory, optionally on
// a recurring schedule with retention. The standard openssl format means a
// backup can be restored anywhere with a one-line command (see the break-glass /
// disaster-recovery runbook) — no Fleet-specific tooling required.
package backup

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"log/slog"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/store"
)

const (
	settingKey = "backup_policy"
	filePrefix = "fleet-backup-"
	fileSuffix = ".sql.enc"
)

// Policy is the persisted scheduled-backup configuration.
type Policy struct {
	Enabled        bool `json:"enabled"`
	IntervalHours  int  `json:"intervalHours"`
	RetentionCount int  `json:"retentionCount"`
}

// Info describes a stored backup file.
type Info struct {
	Name      string    `json:"name"`
	Size      int64     `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
}

// Service creates and manages backups.
type Service struct {
	store *store.Store
	cfg   *config.Config
	log   *slog.Logger
	mu    sync.Mutex // serialize backup creation
}

func New(st *store.Store, cfg *config.Config, log *slog.Logger) *Service {
	return &Service{store: st, cfg: cfg, log: log}
}

// pgEnv converts a postgres connection URL into libpq environment variables, so
// pg_dump receives credentials via the environment rather than argv — where the
// password would otherwise be visible to any local user via ps / /proc.
func pgEnv(dbURL string) ([]string, error) {
	u, err := url.Parse(dbURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	env := []string{}
	if h := u.Hostname(); h != "" {
		env = append(env, "PGHOST="+h)
	}
	if p := u.Port(); p != "" {
		env = append(env, "PGPORT="+p)
	}
	if user := u.User.Username(); user != "" {
		env = append(env, "PGUSER="+user)
	}
	if pass, ok := u.User.Password(); ok {
		env = append(env, "PGPASSWORD="+pass)
	}
	if db := strings.TrimPrefix(u.Path, "/"); db != "" {
		env = append(env, "PGDATABASE="+db)
	}
	if sslmode := u.Query().Get("sslmode"); sslmode != "" {
		env = append(env, "PGSSLMODE="+sslmode)
	}
	return env, nil
}

func (s *Service) passphrase() string {
	if s.cfg.BackupPassphrase != "" {
		return s.cfg.BackupPassphrase
	}
	return string(s.cfg.CAKeyPassphrase)
}

// LoadPolicy returns the stored policy (sane defaults if unset).
func (s *Service) LoadPolicy(ctx context.Context) Policy {
	p := Policy{Enabled: false, IntervalHours: 24, RetentionCount: 7}
	if raw, err := s.store.GetSetting(ctx, settingKey); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &p)
	}
	if p.IntervalHours < 1 {
		p.IntervalHours = 24
	}
	if p.RetentionCount < 1 {
		p.RetentionCount = 7
	}
	return p
}

// SavePolicy persists the policy.
func (s *Service) SavePolicy(ctx context.Context, p Policy) error {
	return s.store.SetSetting(ctx, settingKey, p)
}

// Create produces a new encrypted backup, applies retention, and returns its
// metadata.
func (s *Service) Create(ctx context.Context) (*Info, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := exec.LookPath("pg_dump"); err != nil {
		return nil, fmt.Errorf("pg_dump not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		return nil, fmt.Errorf("openssl not available")
	}
	pass := s.passphrase()
	if pass == "" {
		return nil, fmt.Errorf("no backup passphrase configured")
	}
	// The backup contains every at-rest secret (CA key, credentials, MFA, OIDC/
	// LDAP/SMTP config). In production it must be encrypted with a passphrase
	// distinct from the CA passphrase, so one leaked secret can't both decrypt the
	// backup and unlock the CA key it carries.
	if s.cfg.IsProduction() && (s.cfg.BackupPassphrase == "" || s.cfg.BackupPassphrase == string(s.cfg.CAKeyPassphrase)) {
		return nil, fmt.Errorf("set a distinct FLEET_BACKUP_PASSPHRASE (must differ from the CA passphrase) to create backups in production")
	}
	if err := os.MkdirAll(s.cfg.BackupDir, 0o700); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}

	name := filePrefix + time.Now().Format("20060102-150405") + fileSuffix
	tmp := filepath.Join(s.cfg.BackupDir, "."+name+".part")
	final := filepath.Join(s.cfg.BackupDir, name)

	cctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()

	dumpEnv, derr := pgEnv(s.cfg.DatabaseURL)
	if derr != nil {
		return nil, derr
	}
	dump := exec.CommandContext(cctx, "pg_dump", "--no-owner", "--clean", "--if-exists")
	dump.Env = append(os.Environ(), dumpEnv...)
	enc := exec.CommandContext(cctx, "openssl", "enc", "-aes-256-cbc", "-pbkdf2", "-salt", "-pass", "env:FLEET_BK_PASS")
	enc.Env = append(os.Environ(), "FLEET_BK_PASS="+pass)

	pipe, err := dump.StdoutPipe()
	if err != nil {
		return nil, err
	}
	enc.Stdin = pipe

	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	enc.Stdout = out
	var encErr strings.Builder
	enc.Stderr = &encErr

	if err := enc.Start(); err != nil {
		out.Close()
		os.Remove(tmp)
		return nil, err
	}
	if err := dump.Start(); err != nil {
		out.Close()
		os.Remove(tmp)
		return nil, err
	}
	dumpErr := dump.Wait()
	encWaitErr := enc.Wait()
	out.Close()

	if dumpErr != nil || encWaitErr != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("backup failed: pg_dump=%v openssl=%v %s", dumpErr, encWaitErr, encErr.String())
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return nil, err
	}

	s.applyRetention(ctx)

	fi, err := os.Stat(final)
	if err != nil {
		return nil, err
	}
	s.log.Info("backup created", "name", name, "size", fi.Size())
	return &Info{Name: name, Size: fi.Size(), CreatedAt: fi.ModTime()}, nil
}

// List returns stored backups, newest first.
func (s *Service) List(ctx context.Context) ([]Info, error) {
	entries, err := os.ReadDir(s.cfg.BackupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []Info{}, nil
		}
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), filePrefix) || !strings.HasSuffix(e.Name(), fileSuffix) {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Name: e.Name(), Size: fi.Size(), CreatedAt: fi.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Path resolves a backup file name to an absolute path, rejecting traversal.
func (s *Service) Path(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, "/\\") || !strings.HasPrefix(name, filePrefix) {
		return "", fmt.Errorf("invalid backup name")
	}
	return filepath.Join(s.cfg.BackupDir, name), nil
}

func (s *Service) applyRetention(ctx context.Context) {
	keep := s.LoadPolicy(ctx).RetentionCount
	items, err := s.List(ctx)
	if err != nil {
		return
	}
	for i, it := range items {
		if i < keep {
			continue
		}
		_ = os.Remove(filepath.Join(s.cfg.BackupDir, it.Name))
	}
}

// Run drives the scheduled-backup loop until ctx is cancelled, checking hourly
// whether a backup is due (enabled + older than IntervalHours since the latest).
// Run drives the scheduled-backup loop. leader gates the singleton backup so only the
// leader runs it in a multi-instance (HA) deployment; pass nil for single-instance.
func (s *Service) Run(ctx context.Context, leader func() bool) {
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			t.Reset(time.Hour)
			if leader != nil && !leader() {
				continue
			}
			s.maybeBackup(ctx)
		}
	}
}

func (s *Service) maybeBackup(ctx context.Context) {
	p := s.LoadPolicy(ctx)
	if !p.Enabled {
		return
	}
	items, err := s.List(ctx)
	if err != nil {
		return
	}
	due := len(items) == 0 || time.Since(items[0].CreatedAt) >= time.Duration(p.IntervalHours)*time.Hour
	if !due {
		return
	}
	if _, err := s.Create(ctx); err != nil {
		s.log.Warn("scheduled backup failed", "err", err)
	}
}

// readFile streams a stored backup (used by the download handler).
func (s *Service) Open(name string) (io.ReadCloser, int64, error) {
	path, err := s.Path(name)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, err
	}
	return f, fi.Size(), nil
}
