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

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// How long a scan of an unchanged digest stays good when the vulnerability
// database's build string is unavailable. A digest's contents never change, so
// this is a backstop rather than the primary rule -- the database moving is what
// actually makes a result stale.
const containerScanMaxAge = 7 * 24 * time.Hour

// How many images to scan in one pass.
//
// grype fetches each image from its registry, so a pass is bandwidth, disk and
// registry rate-limit pressure. Anonymous Docker Hub pulls are limited, and a
// sweep that trips that limit fails in a way that looks like a broken scanner
// rather than a throttled one. A bounded pass that makes progress every day
// beats an unbounded one that gets refused halfway.
const containerScanBatch = 25

// ScanContainerImages scans the container images running on the fleet that need
// it, and records what it finds.
//
// Deduplicated by digest: the same image runs in many places and scanning it per
// host would multiply the cost for an identical answer.
//
// Returns how many were scanned and how many failed. Never fatal -- this runs on
// a schedule beside everything else, and a registry that will not answer is not
// a reason to stop.
func (s *Service) ScanContainerImages(ctx context.Context) (scanned, failed int) {
	refs, err := s.store.DistinctContainerImages(ctx)
	if err != nil {
		s.log.Warn("container scan: listing images", "err", err)
		return 0, 0
	}
	if len(refs) == 0 {
		return 0, 0
	}

	// Which database produced the last results. A digest that has not changed
	// still needs rescanning when the DATA has: a new database can turn a clean
	// image into a vulnerable one without anybody touching the image.
	dbBuilt := s.currentDBBuilt(ctx)

	// Both builds of every rebuilt image go first, and are scanned even when no host
	// runs the new one yet: the comparison the Updates page shows for a rebuild needs
	// the package list of each, and at this batch size the whole fleet takes days.
	rebuilds, rerr := s.store.RebuildImageRefs(ctx)
	if rerr != nil {
		s.log.Warn("container scan: listing rebuilt images", "err", rerr)
	}
	refs = prioritise(rebuilds, refs)

	stale, err := s.store.StaleContainerImages(ctx, refs, dbBuilt, containerScanMaxAge)
	if err != nil {
		s.log.Warn("container scan: selecting stale images", "err", err)
		return 0, 0
	}
	if len(stale) > containerScanBatch {
		stale = stale[:containerScanBatch]
	}

	for _, ref := range stale {
		if ctx.Err() != nil {
			return scanned, failed
		}
		res, serr := s.scanImage(ctx, ref.Image)
		rec := store.ContainerImageScan{Digest: ref.Digest, Image: ref.Image}
		if serr != nil {
			// Recorded, not dropped. An image that could not be pulled -- no
			// credentials, rate limited, deleted from the registry -- must not
			// read as an image with no vulnerabilities, and the reason is what
			// tells an operator which of those it was.
			rec.Error = truncate(serr.Error(), 500)
			failed++
		} else {
			rec.Findings = res.Findings
			rec.DBBuilt = res.DBBuilt
			rec.Packages = res.Packages
			for _, f := range res.Findings {
				switch strings.ToLower(f.Severity) {
				case "critical":
					rec.Critical++
				case "high":
					rec.High++
				case "medium":
					rec.Medium++
				case "low", "negligible":
					rec.Low++
				}
			}
			scanned++
		}
		if err := s.store.UpsertContainerImageScan(ctx, rec); err != nil {
			s.log.Warn("container scan: saving result", "digest", ref.Digest, "err", err)
		}
	}
	if scanned > 0 || failed > 0 {
		s.log.Info("container image scan", "scanned", scanned, "failed", failed,
			"stale", len(stale), "total", len(refs))
	}
	return scanned, failed
}

// currentDBBuilt reports the vulnerability database's build string, or "" if it
// cannot be determined. Best-effort: without it the age backstop still applies.
func (s *Service) currentDBBuilt(ctx context.Context) string {
	out, err := s.DBStatus(ctx)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Built:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

type imageScanResult struct {
	Findings []models.VulnFinding `json:"findings"`
	DBBuilt  string               `json:"dbBuilt"`
	// Packages is every installed package (nil from a scanner that predates it).
	Packages []store.ImagePackage `json:"packages"`
}

// scanImage asks the sidecar to scan one digest-pinned reference.
func (s *Service) scanImage(ctx context.Context, ref string) (*imageScanResult, error) {
	body, _ := json.Marshal(map[string]string{"image": ref})
	// A pull plus a scan, so this gets the long-timeout client rather than the
	// per-host one -- and a context detached from the inbound request, for the
	// same reason the database operations are: a scheduled sweep has no inbound
	// request, and a future caller with one must not cap this at sixty seconds.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url("/scan-image"), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 20 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scanner unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scan failed (%d): %s", resp.StatusCode,
			truncate(strings.TrimSpace(string(raw)), 300))
	}
	var out imageScanResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("parse scanner response: %w", err)
	}
	return &out, nil
}

// prioritise puts first before rest, dropping any digest already present. Order is
// kept because StaleContainerImages keeps it, and the batch cut is taken from the
// front.
func prioritise(first, rest []store.ImageRef) []store.ImageRef {
	seen := map[string]bool{}
	out := make([]store.ImageRef, 0, len(first)+len(rest))
	for _, list := range [][]store.ImageRef{first, rest} {
		for _, r := range list {
			if r.Digest == "" || seen[r.Digest] {
				continue
			}
			seen[r.Digest] = true
			out = append(out, r)
		}
	}
	return out
}
