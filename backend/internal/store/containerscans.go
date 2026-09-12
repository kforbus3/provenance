package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// ContainerImageScan is what a scan of one image digest found.
type ContainerImageScan struct {
	Digest    string               `json:"digest"`
	Image     string               `json:"image,omitempty"`
	Findings  []models.VulnFinding `json:"findings,omitempty"`
	Critical  int                  `json:"critical"`
	High      int                  `json:"high"`
	Medium    int                  `json:"medium"`
	Low       int                  `json:"low"`
	DBBuilt   string               `json:"dbBuilt,omitempty"`
	Error     string               `json:"error,omitempty"`
	ScannedAt time.Time            `json:"scannedAt"`
}

// ImageRef is one image a host is running, as the scanner needs it.
type ImageRef struct {
	Digest string
	// Image is repository@digest -- what grype is actually given. A bare digest
	// is not a pullable reference; the repository says where to get the bytes.
	Image string
}

// DistinctContainerImages returns every digest-pinned image running anywhere,
// once each.
//
// Once each is the point. The same image runs on many hosts, grype fetches it
// from its registry to scan it, and scanning it per host would multiply
// bandwidth, disk and registry rate-limit pressure for an identical answer.
//
// Containers whose digest could not be resolved are skipped rather than guessed
// at: a reference built from a tag would scan whatever that tag points at now,
// which is not necessarily what is running.
func (s *Store) DistinctContainerImages(ctx context.Context) ([]ImageRef, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT c->>'digest' AS digest,
		       (c->>'repository') || '@' || (c->>'digest') AS image
		FROM host_inventory hi,
		     LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
		WHERE COALESCE(c->>'digest','') <> ''
		  AND COALESCE(c->>'repository','') <> ''
		ORDER BY digest`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImageRef{}
	for rows.Next() {
		var r ImageRef
		if err := rows.Scan(&r.Digest, &r.Image); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpsertContainerImageScan records the result of scanning one digest.
func (s *Store) UpsertContainerImageScan(ctx context.Context, in ContainerImageScan) error {
	var findings []byte
	if in.Findings != nil {
		findings, _ = json.Marshal(in.Findings)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO container_image_scans
			(digest, image, findings, critical, high, medium, low, db_built, error, scanned_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
		ON CONFLICT (digest) DO UPDATE SET
			image=EXCLUDED.image, findings=EXCLUDED.findings,
			critical=EXCLUDED.critical, high=EXCLUDED.high,
			medium=EXCLUDED.medium, low=EXCLUDED.low,
			db_built=EXCLUDED.db_built, error=EXCLUDED.error, scanned_at=now()`,
		in.Digest, in.Image, findings, in.Critical, in.High, in.Medium, in.Low,
		in.DBBuilt, in.Error)
	return err
}

// ContainerImageScans returns what is known about a set of digests.
func (s *Store) ContainerImageScans(ctx context.Context, digests []string) (map[string]ContainerImageScan, error) {
	out := map[string]ContainerImageScan{}
	if len(digests) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT digest, image, critical, high, medium, low, db_built, error, scanned_at
		FROM container_image_scans WHERE digest = ANY($1)`, digests)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ContainerImageScan
		if err := rows.Scan(&r.Digest, &r.Image, &r.Critical, &r.High, &r.Medium,
			&r.Low, &r.DBBuilt, &r.Error, &r.ScannedAt); err != nil {
			return nil, err
		}
		out[r.Digest] = r
	}
	return out, rows.Err()
}

// StaleContainerImages is the subset of refs that need scanning: never scanned,
// scanned before the current vulnerability database was built, or older than
// maxAge.
//
// A digest's contents never change, so re-scanning one is only worth doing when
// the DATA has moved: a new grype database can turn a clean image into a
// vulnerable one without anybody touching the image. maxAge is the backstop for
// when the database build string is unavailable.
func (s *Store) StaleContainerImages(ctx context.Context, refs []ImageRef, dbBuilt string, maxAge time.Duration) ([]ImageRef, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	digests := make([]string, 0, len(refs))
	for _, r := range refs {
		digests = append(digests, r.Digest)
	}
	known, err := s.ContainerImageScans(ctx, digests)
	if err != nil {
		return nil, err
	}
	cutoff := time.Now().Add(-maxAge)
	var stale []ImageRef
	for _, r := range refs {
		prev, seen := known[r.Digest]
		switch {
		case !seen:
			stale = append(stale, r)
		case prev.Error != "":
			// A scan that failed is not a scan. Retrying is the whole point of
			// recording the error rather than an empty result.
			stale = append(stale, r)
		case dbBuilt != "" && prev.DBBuilt != dbBuilt:
			stale = append(stale, r)
		case prev.ScannedAt.Before(cutoff):
			stale = append(stale, r)
		}
	}
	return stale, nil
}
