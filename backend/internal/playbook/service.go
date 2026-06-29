// Package playbook manages Ansible playbooks authored in the UI: storage,
// syntax validation, and linting (Phase 1), with execution against hosts/groups
// to follow. Validation/lint and execution are delegated to a dedicated
// `ansible-runner` sidecar over HTTP so the lean Go backend never needs Python
// or Ansible installed, and the arbitrary-code blast radius stays isolated.
package playbook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/config"
	"github.com/fleet-terminal/backend/internal/store"
)

// Service talks to the ansible-runner sidecar.
type Service struct {
	store  *store.Store
	cfg    *config.Config
	log    *slog.Logger
	client *http.Client
}

// New constructs the playbook service.
func New(st *store.Store, cfg *config.Config, log *slog.Logger) *Service {
	return &Service{
		store:  st,
		cfg:    cfg,
		log:    log,
		client: &http.Client{Timeout: 60 * time.Second},
	}
}

// CheckResult is the outcome of a syntax-check or lint request.
type CheckResult struct {
	OK     bool   `json:"ok"`
	Output string `json:"output"`
}

// runnerURL returns the configured runner base URL, or an error if disabled.
func (s *Service) runnerURL() (string, error) {
	u := strings.TrimRight(s.cfg.AnsibleRunnerURL, "/")
	if u == "" {
		return "", fmt.Errorf("ansible runner not configured")
	}
	return u, nil
}

// SyntaxCheck runs `ansible-playbook --syntax-check` on the content in the
// sidecar. A non-OK result carries the parser error in Output.
func (s *Service) SyntaxCheck(ctx context.Context, content string) (*CheckResult, error) {
	return s.post(ctx, "/syntax-check", content)
}

// Lint runs ansible-lint on the content in the sidecar.
func (s *Service) Lint(ctx context.Context, content string) (*CheckResult, error) {
	return s.post(ctx, "/lint", content)
}

// Healthy reports whether the runner sidecar is reachable.
func (s *Service) Healthy(ctx context.Context) bool {
	base, err := s.runnerURL()
	if err != nil {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}

func (s *Service) post(ctx context.Context, path, content string) (*CheckResult, error) {
	base, err := s.runnerURL()
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"content": content})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ansible runner unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ansible runner error (%d): %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var res CheckResult
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("decode runner response: %w", err)
	}
	return &res, nil
}
