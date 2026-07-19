// Package msrc maps Windows KB article numbers to the CVEs they remediate, using
// Microsoft's Security Update Guide (CVRF documents). It supports two ways to
// populate the mapping: fetching online from api.msrc.microsoft.com, or importing
// CVRF JSON/zip offline for air-gapped deployments. The flattened mapping is stored
// in Postgres (msrc_updates); the Windows vulnerability scanner looks up a host's
// missing KBs to attach real CVE IDs, severity, and CVSS to its findings.
package msrc

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/store"
)

// --- CVRF JSON (only the fields we need) ---

type cvrfValue struct {
	Value string `json:"Value"`
}

type cvrfDoc struct {
	DocumentTracking struct {
		Identification struct {
			ID cvrfValue `json:"ID"`
		} `json:"Identification"`
	} `json:"DocumentTracking"`
	Vulnerability []cvrfVuln `json:"Vulnerability"`
}

type cvrfVuln struct {
	Title   cvrfValue `json:"Title"`
	CVE     string    `json:"CVE"`
	Threats []struct {
		Type        int       `json:"Type"`
		Description cvrfValue `json:"Description"`
	} `json:"Threats"`
	CVSSScoreSets []struct {
		BaseScore float64 `json:"BaseScore"`
		Vector    string  `json:"Vector"`
	} `json:"CVSSScoreSets"`
	Remediations []struct {
		Type        int       `json:"Type"`
		Description cvrfValue `json:"Description"`
		SubType     string    `json:"SubType"`
	} `json:"Remediations"`
}

var severityLabels = map[string]bool{"critical": true, "important": true, "moderate": true, "low": true}

// ParseCVRF flattens a single CVRF document into KB→CVE entries: one entry per
// (KB, CVE) pair, carrying the CVE's severity and highest CVSS base score.
func ParseCVRF(data []byte) ([]models.MSRCEntry, error) {
	var doc cvrfDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse CVRF: %w", err)
	}
	release := strings.TrimSpace(doc.DocumentTracking.Identification.ID.Value)
	var out []models.MSRCEntry
	for _, v := range doc.Vulnerability {
		cve := strings.TrimSpace(v.CVE)
		if cve == "" {
			continue
		}
		// Severity: the Threat whose description is a known MSRC severity label
		// (robust to the Threat Type enum).
		var sev string
		for _, t := range v.Threats {
			if severityLabels[strings.ToLower(strings.TrimSpace(t.Description.Value))] {
				sev = strings.TrimSpace(t.Description.Value)
				break
			}
		}
		// Highest CVSS base score across score sets.
		var cvss float64
		var vector string
		for _, c := range v.CVSSScoreSets {
			if c.BaseScore > cvss {
				cvss = c.BaseScore
				vector = c.Vector
			}
		}
		// KBs that remediate this CVE (a remediation whose description is a bare KB number).
		kbs := map[string]bool{}
		for _, r := range v.Remediations {
			if kb := kbNumber(r.Description.Value); kb != "" {
				kbs[kb] = true
			}
		}
		for kb := range kbs {
			out = append(out, models.MSRCEntry{
				KB: kb, CVE: cve, Severity: sev, CVSS: cvss, Vector: vector,
				Title: strings.TrimSpace(v.Title.Value), Release: release,
			})
		}
	}
	return out, nil
}

// kbNumber returns the digits of a KB reference ("KB5099536" or "5099536" → "5099536"),
// or "" if the value isn't a bare KB number.
func kbNumber(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.ToUpper(s), "KB")
	if len(s) < 5 || len(s) > 8 {
		return ""
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return ""
		}
	}
	return s
}

// --- online client ---

// Client fetches CVRF data from the MSRC Security Update Guide API.
type Client struct {
	base string
	http *http.Client
}

func NewClient(base string) *Client {
	if strings.TrimSpace(base) == "" {
		base = "https://api.msrc.microsoft.com"
	}
	return &Client{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 60 * time.Second}}
}

// Releases returns the available release ids (e.g. "2026-Jul"), newest first.
func (c *Client) Releases(ctx context.Context) ([]string, error) {
	body, err := c.get(ctx, c.base+"/cvrf/v3.0/updates")
	if err != nil {
		return nil, err
	}
	var resp struct {
		Value []struct {
			ID string `json:"ID"`
		} `json:"value"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse releases: %w", err)
	}
	out := make([]string, 0, len(resp.Value))
	for _, v := range resp.Value {
		if v.ID != "" {
			out = append(out, v.ID)
		}
	}
	// The API returns oldest-first; reverse to newest-first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// CVRF fetches the CVRF document for one release.
func (c *Client) CVRF(ctx context.Context, release string) ([]byte, error) {
	return c.get(ctx, c.base+"/cvrf/v3.0/cvrf/"+release)
}

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("msrc request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("msrc %s: status %d", url, resp.StatusCode)
	}
	return body, nil
}

// --- service ---

// Service populates the msrc_updates mapping online or from an offline bundle.
type Service struct {
	store  *store.Store
	client *Client
	log    *slog.Logger
	months int // how many recent releases to fetch on an online update
}

func New(st *store.Store, apiURL string, months int, log *slog.Logger) *Service {
	if months <= 0 {
		months = 12
	}
	return &Service{store: st, client: NewClient(apiURL), log: log, months: months}
}

// UpdateOnline fetches the most recent `months` CVRF releases and upserts their
// KB→CVE mappings. Returns the number of entries stored.
func (s *Service) UpdateOnline(ctx context.Context) (int, error) {
	releases, err := s.client.Releases(ctx)
	if err != nil {
		return 0, err
	}
	if len(releases) > s.months {
		releases = releases[:s.months]
	}
	var all []models.MSRCEntry
	for _, rel := range releases {
		data, err := s.client.CVRF(ctx, rel)
		if err != nil {
			s.log.Warn("msrc: fetch release", "release", rel, "err", err)
			continue
		}
		rows, err := ParseCVRF(data)
		if err != nil {
			s.log.Warn("msrc: parse release", "release", rel, "err", err)
			continue
		}
		all = append(all, rows...)
	}
	if len(all) == 0 {
		return 0, fmt.Errorf("no MSRC data retrieved")
	}
	if err := s.store.UpsertMSRC(ctx, all); err != nil {
		return 0, err
	}
	return len(all), nil
}

// Import loads CVRF data from an offline bundle: a zip of .json CVRF documents, a
// JSON array of documents, or a single CVRF JSON document. Returns entries stored.
func (s *Service) Import(ctx context.Context, data []byte) (int, error) {
	docs, err := splitDocs(data)
	if err != nil {
		return 0, err
	}
	var all []models.MSRCEntry
	for _, d := range docs {
		rows, err := ParseCVRF(d)
		if err != nil {
			s.log.Warn("msrc import: parse doc", "err", err)
			continue
		}
		all = append(all, rows...)
	}
	if len(all) == 0 {
		return 0, fmt.Errorf("no MSRC entries parsed from import")
	}
	if err := s.store.UpsertMSRC(ctx, all); err != nil {
		return 0, err
	}
	return len(all), nil
}

// splitDocs turns an uploaded payload into individual CVRF JSON documents. It
// accepts a zip archive (each .json entry is a document), a top-level JSON array of
// documents, or a single JSON document.
func splitDocs(data []byte) ([][]byte, error) {
	if len(data) >= 2 && data[0] == 'P' && data[1] == 'K' { // zip magic
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("read zip: %w", err)
		}
		var out [][]byte
		for _, f := range zr.File {
			if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			b, err := io.ReadAll(io.LimitReader(rc, 64<<20))
			rc.Close()
			if err != nil {
				return nil, err
			}
			out = append(out, b)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("zip contains no .json documents")
		}
		return out, nil
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("parse JSON array: %w", err)
		}
		out := make([][]byte, 0, len(arr))
		for _, d := range arr {
			out = append(out, d)
		}
		return out, nil
	}
	return [][]byte{data}, nil
}
