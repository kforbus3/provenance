package netscan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// ErrNotConfigured is returned by every sidecar call when no token is set. The
// sidecar refuses requests without one, so calling it would only produce a less
// useful error.
var ErrNotConfigured = errors.New("network scanning is not configured: set PROV_NETSCAN_TOKEN " +
	"(the same value for the backend and the net-scanner) and restart both")

type sidecar struct {
	url, token string
	client     *http.Client
}

func (c *sidecar) do(ctx context.Context, method, path string, body io.Reader, contentType string,
	client *http.Client, out any, hdr ...string) error {
	if c.token == "" {
		return ErrNotConfigured
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("X-Netscan-Token", c.token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] != "" {
			req.Header.Set(hdr[i], hdr[i+1])
		}
	}
	if client == nil {
		client = c.client
	}
	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
			return fmt.Errorf("the network scanner did not answer in time: %w", err)
		}
		return fmt.Errorf("network scanner unreachable: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error  string `json:"error"`
			Output string `json:"output"`
		}
		_ = json.Unmarshal(b, &e)
		msg := e.Error
		if msg == "" {
			msg = e.Output
		}
		if msg == "" {
			msg = strings.TrimSpace(string(b))
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return fmt.Errorf("the network scanner refused the token: PROV_NETSCAN_TOKEN differs between the backend and the net-scanner")
		case http.StatusConflict:
			return fmt.Errorf("%s (Vulnerabilities -> Network scanning -> update or import templates)", truncate(msg, 300))
		}
		return fmt.Errorf("network scanner error (%d): %s", resp.StatusCode, truncate(msg, 300))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(b, out)
}

type scanRequest struct {
	Target          string `json:"target"`
	TCPPorts        any    `json:"tcpPorts"`
	UDP             bool   `json:"udp"`
	AliveProbePorts []int  `json:"aliveProbePorts,omitempty"`
	// NucleiRate is 0 to take the sidecar's default.
	NucleiRate int `json:"nucleiRate,omitempty"`
}

func (c *sidecar) scan(ctx context.Context, r scanRequest) (*sidecarResult, error) {
	b, _ := json.Marshal(r)
	var out sidecarResult
	if err := c.do(ctx, http.MethodPost, "/scan", bytes.NewReader(b), "application/json", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *sidecar) discover(ctx context.Context, cidr string) ([]string, error) {
	b, _ := json.Marshal(map[string]string{"cidr": cidr})
	var out struct {
		Addresses []string `json:"addresses"`
	}
	if err := c.do(ctx, http.MethodPost, "/discover", bytes.NewReader(b), "application/json", nil, &out); err != nil {
		return nil, err
	}
	return out.Addresses, nil
}

// Health is the sidecar's /healthz answer.
type Health struct {
	OK        bool   `json:"ok"`
	Overlay   string `json:"overlay"` // ok | no-route | not-configured
	Templates bool   `json:"templates"`
}

func (c *sidecar) health(ctx context.Context) (*Health, error) {
	// /healthz is not behind the token, but a deployment with no token cannot scan,
	// and saying so here keeps the status page from reporting a healthy scanner.
	if c.token == "" {
		return nil, ErrNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url+"/healthz", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("network scanner unreachable: %w", err)
	}
	defer resp.Body.Close()
	var h Health
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h); err != nil {
		return nil, fmt.Errorf("network scanner health: %w", err)
	}
	return &h, nil
}

// TemplatesStatus is the sidecar's template state.
type TemplatesStatus struct {
	Present                     bool   `json:"present"`
	Version                     string `json:"version,omitempty"`
	Source                      string `json:"source,omitempty"`
	UpdatedAt                   string `json:"updatedAt,omitempty"`
	ExcludedCredentialTemplates int    `json:"excludedCredentialTemplates"`
}

func (c *sidecar) templatesStatus(ctx context.Context) (*TemplatesStatus, error) {
	var st TemplatesStatus
	if err := c.do(ctx, http.MethodGet, "/templates/status", nil, "", nil, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// templatesPost runs an update or import. Detached from the inbound request's
// deadline for the same reason as vulnscan's DB operations: every route sits behind
// a 60-second timeout middleware, and a template download takes longer.
func (c *sidecar) templatesPost(ctx context.Context, path string, body io.Reader, contentType, version string) (*TemplatesStatus, error) {
	ctx = context.WithoutCancel(ctx)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	var st TemplatesStatus
	err := c.do(ctx, http.MethodPost, path, body, contentType, &http.Client{Timeout: 20 * time.Minute}, &st,
		"X-Templates-Version", version)
	if err != nil {
		return nil, err
	}
	st.Present = true
	return &st, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
