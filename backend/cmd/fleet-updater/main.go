// Command fleet-updater is the privileged sidecar that applies signed Fleet Terminal
// upgrade bundles by swapping container images over the Docker socket. It is the ONLY
// component with Docker access; the backend hands it a staged, already-verified bundle
// and this process independently re-verifies the signature before touching anything.
// Kept deliberately tiny and single-purpose to bound the trust it holds.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/release"
)

// Config is resolved from the environment (set in the compose service definition).
type Config struct {
	Listen       string
	Token        string
	UpdatesDir   string
	Project      string
	ComposeFiles []string
	EnvFile      string
	BackendURL   string
	// BackendServices are the compose service names for the backend component. One for
	// single-host ("backend"); multiple for an HA stack (e.g. backend1,backend2), which
	// the updater rolls one at a time for an additive release.
	BackendServices []string
	HealthTimeout   time.Duration
}

func loadConfig() Config {
	return Config{
		Listen:          env("FLEET_UPDATER_LISTEN", ":9000"),
		Token:           os.Getenv("FLEET_UPDATER_TOKEN"),
		UpdatesDir:      env("FLEET_UPDATES_DIR", "/var/lib/fleet/updates"),
		Project:         env("FLEET_UPDATER_PROJECT", "fleet-terminal"),
		ComposeFiles:    splitList(env("FLEET_UPDATER_COMPOSE_FILES", "/compose/docker-compose.yml:/compose/docker-compose.jumphost.yml")),
		EnvFile:         env("FLEET_UPDATER_ENV_FILE", "/compose/.env"),
		BackendURL:      env("FLEET_UPDATER_BACKEND_URL", "http://backend:8080"),
		BackendServices: splitList(env("FLEET_UPDATER_BACKENDS", "backend")),
		HealthTimeout:   4 * time.Minute,
	}
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stdout, nil))
	cfg := loadConfig()
	trusted, err := release.TrustedKeys(os.Getenv("FLEET_RELEASE_TRUST_KEYS"))
	if err != nil {
		log.Error("fleet-updater: bad FLEET_RELEASE_TRUST_KEYS", "err", err)
		os.Exit(1)
	}
	if len(trusted) == 0 {
		log.Warn("fleet-updater: no trusted release keys configured — every upgrade will be rejected until a key is set")
	}
	if cfg.Token == "" {
		log.Warn("fleet-updater: FLEET_UPDATER_TOKEN is empty — set it so only the backend can trigger upgrades")
	}

	u := &Updater{
		cfg:     cfg,
		docker:  &execDocker{project: cfg.Project, composeFiles: cfg.ComposeFiles, envFile: cfg.EnvFile, log: log},
		health:  &httpHealth{},
		trusted: trusted,
		status:  Status{State: "idle"},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(cfg.Token, r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, u.getStatus())
	})
	mux.HandleFunc("/apply", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !authOK(cfg.Token, r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var req ApplyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Bundle == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if u.busy() {
			http.Error(w, "an upgrade is already in progress", http.StatusConflict)
			return
		}
		go u.Apply(context.Background(), req)
		w.WriteHeader(http.StatusAccepted)
	})

	log.Info("fleet-updater listening", "addr", cfg.Listen, "project", cfg.Project)
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Error("fleet-updater server exited", "err", err)
		os.Exit(1)
	}
}

// authOK checks the shared updater token in constant time. An empty configured token
// means "no auth" (dev only); a set token is required.
func authOK(token string, r *http.Request) bool {
	if token == "" {
		return true
	}
	got := r.Header.Get("X-Updater-Token")
	return subtle.ConstantTimeCompare([]byte(got), []byte(token)) == 1
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ':' || r == ',' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
