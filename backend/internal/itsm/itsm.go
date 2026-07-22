// Package itsm opens change/incident tickets in an IT service-management system
// (ServiceNow or Jira) and links them to Fleet access approvals, so privileged-access
// requests carry a ticket reference for change management. Implemented against the
// vendor REST APIs directly (basic auth over HTTPS) — no SDK.
package itsm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Providers.
const (
	ProviderServiceNow = "servicenow"
	ProviderJira       = "jira"
)

// Config configures the ITSM connection. Token is the ServiceNow password or the Jira
// API token; User is the ServiceNow user or the Jira account email; Project is the
// ServiceNow table (default "incident") or the Jira project key.
type Config struct {
	Provider string `json:"provider"`
	BaseURL  string `json:"baseUrl"`
	User     string `json:"user"`
	Token    string `json:"-"` // resolved from the sealed store value; never serialized
	Project  string `json:"project"`
	Enabled  bool   `json:"enabled"`
}

// Configured reports whether enough is set to talk to the ITSM.
func (c Config) Configured() bool {
	return c.Enabled && c.Provider != "" && strings.TrimSpace(c.BaseURL) != "" &&
		strings.TrimSpace(c.User) != "" && strings.TrimSpace(c.Token) != ""
}

func Supported(provider string) bool {
	return provider == ProviderServiceNow || provider == ProviderJira
}

// Client talks to one configured ITSM.
type Client struct {
	cfg  Config
	http *http.Client
}

func New(cfg Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 15 * time.Second}}
}

// CreateTicket opens a ticket and returns its human reference (e.g. "INC0010001" /
// "OPS-42") and a browser URL.
func (c *Client) CreateTicket(ctx context.Context, summary, description string) (ref, url string, err error) {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	switch c.cfg.Provider {
	case ProviderServiceNow:
		table := c.cfg.Project
		if table == "" {
			table = "incident"
		}
		body := map[string]string{"short_description": summary, "description": description}
		var out struct {
			Result struct {
				Number string `json:"number"`
				SysID  string `json:"sys_id"`
			} `json:"result"`
		}
		if err := c.do(ctx, http.MethodPost, base+"/api/now/table/"+table, body, &out); err != nil {
			return "", "", err
		}
		return out.Result.Number, fmt.Sprintf("%s/nav_to.do?uri=%s.do?sys_id=%s", base, table, out.Result.SysID), nil

	case ProviderJira:
		body := map[string]any{"fields": map[string]any{
			"project":     map[string]string{"key": c.cfg.Project},
			"summary":     summary,
			"description": description,
			"issuetype":   map[string]string{"name": "Task"},
		}}
		var out struct {
			Key string `json:"key"`
		}
		if err := c.do(ctx, http.MethodPost, base+"/rest/api/2/issue", body, &out); err != nil {
			return "", "", err
		}
		return out.Key, base + "/browse/" + out.Key, nil

	default:
		return "", "", fmt.Errorf("itsm: unsupported provider %q", c.cfg.Provider)
	}
}

// Test verifies connectivity and credentials without creating a ticket.
func (c *Client) Test(ctx context.Context) error {
	base := strings.TrimRight(c.cfg.BaseURL, "/")
	var probe string
	switch c.cfg.Provider {
	case ProviderServiceNow:
		table := c.cfg.Project
		if table == "" {
			table = "incident"
		}
		probe = base + "/api/now/table/" + table + "?sysparm_limit=1"
	case ProviderJira:
		probe = base + "/rest/api/2/myself"
	default:
		return fmt.Errorf("itsm: unsupported provider %q", c.cfg.Provider)
	}
	return c.do(ctx, http.MethodGet, probe, nil, nil)
}

func (c *Client) do(ctx context.Context, method, url string, body any, out any) error {
	var r io.Reader
	if body != nil {
		buf, _ := json.Marshal(body)
		r = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.cfg.User+":"+c.cfg.Token)))
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("itsm(%s): request failed: %w", c.cfg.Provider, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("itsm(%s): HTTP %d: %s", c.cfg.Provider, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("itsm(%s): decode response: %w", c.cfg.Provider, err)
		}
	}
	return nil
}
