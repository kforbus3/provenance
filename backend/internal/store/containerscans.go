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
	// Packages is every installed package, from the scanner. Nil means not
	// collected, which is different from an image with none.
	Packages []ImagePackage `json:"packages,omitempty"`
	// PackagesCollected says whether Packages was recorded, without loading it.
	PackagesCollected bool `json:"-"`
}

// ImagePackage is one installed package in an image ("os" for the base system).
type ImagePackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"`
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
	var findings, packages []byte
	if in.Findings != nil {
		findings, _ = json.Marshal(in.Findings)
	}
	if in.Packages != nil {
		packages, _ = json.Marshal(in.Packages)
	}
	// A failed scan keeps the packages a previous one found: the image's contents did
	// not change because a pull was rate limited.
	_, err := s.pool.Exec(ctx, `
		INSERT INTO container_image_scans
			(digest, image, findings, critical, high, medium, low, db_built, error, scanned_at, packages)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now(), $10)
		ON CONFLICT (digest) DO UPDATE SET
			image=EXCLUDED.image, findings=EXCLUDED.findings,
			critical=EXCLUDED.critical, high=EXCLUDED.high,
			medium=EXCLUDED.medium, low=EXCLUDED.low,
			db_built=EXCLUDED.db_built, error=EXCLUDED.error, scanned_at=now(),
			packages=COALESCE(EXCLUDED.packages, container_image_scans.packages)`,
		in.Digest, in.Image, findings, in.Critical, in.High, in.Medium, in.Low,
		in.DBBuilt, in.Error, packages)
	return err
}

// ContainerImageScans returns what is known about a set of digests.
func (s *Store) ContainerImageScans(ctx context.Context, digests []string) (map[string]ContainerImageScan, error) {
	out := map[string]ContainerImageScan{}
	if len(digests) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT digest, image, critical, high, medium, low, db_built, error, scanned_at,
		       packages IS NOT NULL
		FROM container_image_scans WHERE digest = ANY($1)`, digests)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ContainerImageScan
		if err := rows.Scan(&r.Digest, &r.Image, &r.Critical, &r.High, &r.Medium,
			&r.Low, &r.DBBuilt, &r.Error, &r.ScannedAt, &r.PackagesCollected); err != nil {
			return nil, err
		}
		out[r.Digest] = r
	}
	return out, rows.Err()
}

// ContainerImageScanDetails is ContainerImageScans with the findings and package
// lists, for comparing two builds. Separate because those are large and the list
// view does not need them.
func (s *Store) ContainerImageScanDetails(ctx context.Context, digests []string) (map[string]ContainerImageScan, error) {
	out := map[string]ContainerImageScan{}
	if len(digests) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT digest, image, critical, high, medium, low, db_built, error, scanned_at,
		       COALESCE(findings, 'null'::jsonb), COALESCE(packages, 'null'::jsonb)
		FROM container_image_scans WHERE digest = ANY($1)`, digests)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r ContainerImageScan
		var findings, packages []byte
		if err := rows.Scan(&r.Digest, &r.Image, &r.Critical, &r.High, &r.Medium,
			&r.Low, &r.DBBuilt, &r.Error, &r.ScannedAt, &findings, &packages); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(findings, &r.Findings)
		_ = json.Unmarshal(packages, &r.Packages)
		out[r.Digest] = r
	}
	return out, rows.Err()
}

// RebuildImageRefs is both builds of every rebuilt image: what the tag points at now,
// and what hosts are running under it. They are scanned ahead of everything else, so
// the Updates page can say what a rebuild changed within a day of it appearing
// rather than whenever the batch reaches them.
func (s *Store) RebuildImageRefs(ctx context.Context) ([]ImageRef, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT d.digest, d.repository || '@' || d.digest
		FROM (
			SELECT u.repository, u.current_digest AS digest
			  FROM container_image_updates u
			 WHERE u.status = 'moved' AND COALESCE(u.current_digest,'') <> ''
			UNION
			SELECT u.repository, c->>'digest'
			  FROM container_image_updates u
			  JOIN host_inventory hi ON true,
			       LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
			 WHERE u.status = 'moved'
			   AND c->>'repository' = u.repository AND c->>'tag' = u.tag
			   AND COALESCE(c->>'digest','') <> ''
		) d
		ORDER BY 1`)
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
		case !prev.PackagesCollected:
			// Scanned before package lists were kept: once more, so a rebuild of it
			// can be compared.
			stale = append(stale, r)
		case prev.ScannedAt.Before(cutoff):
			stale = append(stale, r)
		}
	}
	return stale, nil
}
