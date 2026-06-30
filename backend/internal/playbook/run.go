package playbook

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/notify"
)

const (
	defaultRunTimeout = 30 * time.Minute
	// Principal + cert lifetime for a run. The cert only needs to outlive the
	// run; the timeout bounds that.
	runCertTTL = 2 * time.Hour
)

// liveRun holds the in-memory, incrementally-growing output of a run in flight
// so the status endpoint can stream it to the browser by polling. On completion
// the output is persisted and the entry removed.
type liveRun struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (l *liveRun) append(s string) {
	l.mu.Lock()
	l.buf.WriteString(s)
	l.mu.Unlock()
}

func (l *liveRun) snapshot() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// LiveOutput returns the current output for a running run, if it is in flight.
func (s *Service) LiveOutput(id uuid.UUID) (string, bool) {
	v, ok := s.live.Load(id)
	if !ok {
		return "", false
	}
	return v.(*liveRun).snapshot(), true
}

// runHost is one inventory entry sent to the sidecar.
type runHost struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	User    string `json:"user"`
	Port    int    `json:"port"`
}

// runRequest is the body posted to the sidecar's /run endpoint. The credential
// is ephemeral and scoped to this single run.
type runRequest struct {
	Playbook    string    `json:"playbook"`
	PrivateKey  string    `json:"privateKey"`
	Certificate string    `json:"certificate"`
	Hosts       []runHost `json:"hosts"`
	JumpHost    string    `json:"jumpHost"`
	JumpUser    string    `json:"jumpUser"`
	CheckMode   bool      `json:"checkMode"`
	Become      bool      `json:"become"`
	TimeoutSecs int       `json:"timeoutSecs"`
}

// hostAddress picks the address reachable through the jump host: the WireGuard
// overlay address first (as the scan path does), then the management address,
// then the hostname.
func hostAddress(h *models.Host) string {
	for _, a := range []string{h.WGAddress, h.Address, h.Hostname} {
		if strings.TrimSpace(a) != "" {
			return a
		}
	}
	return h.Hostname
}

// Run executes a playbook against the given hosts, streaming output into the
// live buffer and persisting the result. It runs in its own goroutine with a
// fresh (restart-independent) context; the in-memory live buffer does not
// survive a restart, but FailStalePlaybookRuns reconciles the DB row.
func (s *Service) Run(runID uuid.UUID, content string, hosts []*models.Host, checkMode bool) {
	timeout := defaultRunTimeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	live := &liveRun{}
	s.live.Store(runID, live)
	defer s.live.Delete(runID)

	bg := context.Background()
	if err := s.store.StartPlaybookRun(bg, runID); err != nil {
		s.log.Error("playbook run: mark running", "err", err)
	}

	fail := func(msg string) {
		fctx, fcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer fcancel()
		out := live.snapshot()
		if out != "" {
			out += "\n"
		}
		out += msg
		_ = s.store.CompletePlaybookRun(fctx, runID, "failed", out, nil, msg)
	}

	base, err := s.runnerURL()
	if err != nil {
		fail(err.Error())
		return
	}

	// Mint an ephemeral key + cert for this run (privileged `fleet` principal,
	// exactly as scans/remediation use).
	mat, err := s.issuer.SystemKeyMaterial(ctx, []string{"fleet"}, runCertTTL)
	if err != nil {
		fail(fmt.Sprintf("could not issue run credential: %v", err))
		return
	}

	rhosts := make([]runHost, 0, len(hosts))
	for _, h := range hosts {
		rhosts = append(rhosts, runHost{
			Name: h.Hostname, Address: hostAddress(h), User: h.SSHUser, Port: h.SSHPort,
		})
	}

	reqBody := runRequest{
		Playbook:    content,
		PrivateKey:  string(mat.PrivateKeyPEM),
		Certificate: string(mat.CertAuthorizedKey),
		Hosts:       rhosts,
		JumpHost:    s.cfg.JumpHost,
		JumpUser:    s.cfg.JumpUser,
		CheckMode:   checkMode,
		Become:      true,
		TimeoutSecs: int(timeout.Seconds()) - 30,
	}
	body, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/run", bytes.NewReader(body))
	if err != nil {
		fail(err.Error())
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// No client timeout on the streaming response; the context bounds the run.
	streamClient := &http.Client{}
	resp, err := streamClient.Do(req)
	if err != nil {
		fail(fmt.Sprintf("ansible runner unreachable: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		fail(fmt.Sprintf("ansible runner error (%d): %s", resp.StatusCode, strings.TrimSpace(string(buf[:n]))))
		return
	}

	// The sidecar streams NDJSON: {"line":"..."} for each output line, then a
	// final {"done":true,"rc":N}.
	var exitCode *int
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var ev struct {
			Line  string `json:"line"`
			Done  bool   `json:"done"`
			RC    int    `json:"rc"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			continue // ignore malformed frames
		}
		if ev.Done {
			rc := ev.RC
			exitCode = &rc
			if ev.Error != "" {
				live.append(ev.Error + "\n")
			}
			break
		}
		live.append(ev.Line + "\n")
	}
	if err := scanner.Err(); err != nil {
		live.append(fmt.Sprintf("\n[stream error: %v]\n", err))
	}

	status := "completed"
	errMsg := ""
	if exitCode == nil {
		status = "failed"
		errMsg = "run did not report completion"
		if ctx.Err() != nil {
			errMsg = fmt.Sprintf("run exceeded the %s timeout", timeout)
		}
	} else if *exitCode != 0 {
		status = "failed"
		errMsg = fmt.Sprintf("ansible-playbook exited %d", *exitCode)
	}

	pctx, pcancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer pcancel()
	if err := s.store.CompletePlaybookRun(pctx, runID, status, live.snapshot(), exitCode, errMsg); err != nil {
		s.log.Error("playbook run: persist result", "err", err, "run", runID)
	}

	if status == "failed" && s.nfy != nil {
		names := make([]string, 0, len(hosts))
		for _, h := range hosts {
			names = append(names, h.Hostname)
		}
		s.nfy.Notify(context.Background(), notify.Event{
			Type: notify.EventPlaybookFailed, Severity: notify.SeverityError,
			Title: "Playbook run failed",
			Body:  fmt.Sprintf("A playbook run against %s failed: %s", strings.Join(names, ", "), errMsg),
		})
	}
}
