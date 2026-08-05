package vulnscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fleet-terminal/backend/internal/cpe"
	"github.com/fleet-terminal/backend/internal/models"
	"github.com/fleet-terminal/backend/internal/winrm"
)

// --- CycloneDX SBOM ---
//
// Two producers feed the same document type. Windows components carry a CPE,
// because Windows software names only become identifiers through the curated
// mapping in internal/cpe. Linux components carry a purl, because a distribution
// package names exactly one artifact on its own. Both fields are optional so
// each platform emits only what it can honestly assert.

type cdxComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`
	CPE     string `json:"cpe,omitempty"`
	PURL    string `json:"purl,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxMetaComponent struct {
	Type    string `json:"type"`
	BOMRef  string `json:"bom-ref,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxMetadata struct {
	Timestamp string            `json:"timestamp"`
	Tools     []cdxTool         `json:"tools,omitempty"`
	Component *cdxMetaComponent `json:"component,omitempty"`
}

type cdxBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    *cdxMetadata   `json:"metadata,omitempty"`
	Components  []cdxComponent `json:"components"`
}

// newBOM starts a CycloneDX document describing one host.
//
// The metadata.component is what makes this a bill of materials *for a system*
// rather than an unattributed list of packages — a consumer that ingests several
// of these needs to know which machine each describes, and the subject is the
// only place CycloneDX carries that.
func newBOM(hostname, osID, osVersion string) cdxBOM {
	subject := &cdxMetaComponent{
		Type:   "operating-system",
		BOMRef: "host:" + hostname,
		Name:   hostname,
	}
	if osID != "" {
		subject.Name = hostname
		subject.Version = strings.TrimSpace(osID + " " + osVersion)
	}
	return cdxBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: &cdxMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools:     []cdxTool{{Vendor: "Fleet Terminal", Name: "fleet-vulnscan"}},
			Component: subject,
		},
	}
}

// buildLinuxSBOM turns a collected package inventory into a CycloneDX document.
//
// Every installed package becomes a component, not just the ones a scanner can
// match. That is the difference between a vulnerability report and a bill of
// materials: the question "what is on this machine" has to be answered in full,
// including the packages nobody has ever filed a CVE against.
func buildLinuxSBOM(hostname string, inv inventory) ([]byte, int) {
	bom := newBOM(hostname, inv.OSID, inv.OSVersion)
	seen := make(map[string]bool, len(inv.Packages))
	for _, p := range inv.Packages {
		pu := purl(inv, p)
		// Multi-arch systems legitimately install the same name twice (amd64 and
		// i386), so the key includes the architecture rather than the name.
		key := pu
		if key == "" {
			key = p.Name + "\x00" + p.Version + "\x00" + p.Arch
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		bom.Components = append(bom.Components, cdxComponent{
			Type:    "library",
			BOMRef:  key,
			Name:    p.Name,
			Version: p.Version,
			PURL:    pu,
		})
	}
	b, err := json.Marshal(bom)
	if err != nil {
		return nil, 0
	}
	return b, len(bom.Components)
}

// buildWindowsSBOM turns installed apps into a CycloneDX SBOM of the ones with a
// curated CPE mapping. Returns the SBOM JSON and the number of mapped
// (scannable) apps.
//
// Unlike the Linux document this is intentionally lossy: it exists to be fed to
// grype's /scan-sbom endpoint, and an application with no CPE mapping cannot be
// matched against NVD, so including it would inflate the component count without
// making anything scannable.
func buildWindowsSBOM(sw []winrm.Software) ([]byte, int) {
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
