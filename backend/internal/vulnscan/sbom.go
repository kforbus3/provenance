package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/fleet-terminal/backend/internal/cpe"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/winrm"
)

// --- CycloneDX SBOM (minimal) ---

type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version"`
	CPE     string `json:"cpe"`
}

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Components  []cdxComponent `json:"components"`
}

// buildSBOM turns installed apps into a CycloneDX SBOM of the ones with a curated
// CPE mapping. Returns the SBOM JSON and the number of mapped (scannable) apps.
func buildSBOM(sw []winrm.Software) ([]byte, int) {
	var comps []cdxComponent
	seen := map[string]bool{}
	for _, s := range sw {
		vendor, product, ok := cpe.Match(s.Name)
		if !ok {
			continue
		}
		c := cpe.CPE(vendor, product, s.Version)
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		comps = append(comps, cdxComponent{
			Type: "application", Name: product, Version: cpe.NormalizeVersion(s.Version), CPE: c,
		})
	}
	bom := cdxBOM{BOMFormat: "CycloneDX", SpecVersion: "1.5", Version: 1, Components: comps}
	b, _ := json.Marshal(bom)
	return b, len(comps)
}

// scanSBOM posts a CycloneDX SBOM to the grype sidecar's /scan-sbom endpoint and
// returns the CVE findings (grype matches the components' CPEs against NVD).
func (s *Service) scanSBOM(ctx context.Context, sbom []byte) ([]models.VulnFinding, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url("/scan-sbom"), bytes.NewReader(sbom))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scanner unreachable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scanner error (%d): %s", resp.StatusCode, truncate(strings.TrimSpace(string(body)), 300))
	}
	var out sidecarResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parse scanner response: %w", err)
	}
	return out.Findings, nil
}
