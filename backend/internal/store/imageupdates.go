package store

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// ImageUpdate is what a registry last said about one repository:tag pair.
type ImageUpdate struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	// Declared marks a tag that came from a compose file rather than a running
	// container. The two need different treatment: only the declared row can be
	// applied when a host's compose has moved past what it is running.
	Declared bool `json:"declared"`
	// Status is the verdict, as a value rather than as prose.
	//
	// The client used to infer one from Note. "nothing newer with the same shape
	// as 10.11.11; the repository carries other version tags that cannot be
	// ordered against it" means up to date, and rendered identically to a check
	// that failed -- so twenty-two healthy images read as broken. Note stays as
	// the explanation a person reads; this is what code reads.
	Status    string    `json:"status,omitempty"`
	Digest    string    `json:"digest,omitempty"`
	LatestTag string    `json:"latestTag,omitempty"`
	Note      string    `json:"note,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checkedAt"`
}

// TrackedImage is one repository:tag a host is running, and the digest it is
// running it at.
type TrackedImage struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
	// Digest is what the host is running RIGHT NOW. Comparing it against what the
	// tag points at in the registry is how a moved tag -- same tag, new bytes --
	// becomes visible, which a version-number comparison alone can never see.
	Digest string `json:"digest,omitempty"`
	// Declared marks a tag that comes from a managed stack's compose file rather
	// than from a running container.
	//
	// These are not the same question. A compose file pinned to bazarr:v1.6.0
	// whose container still runs :latest -- which is every service pinned but not
	// yet recreated -- is asked about under :latest, so the only answer available
	// is "latest moved again". The version the operator actually chose is never
	// compared against anything, and a real upgrade sitting in the registry is
	// invisible.
	Declared bool `json:"declared,omitempty"`
	// RunningTag is the tag the container is on when that differs from the
	// declared one, so the difference can be stated rather than implied.
	RunningTag string `json:"runningTag,omitempty"`
}

// TrackedImages returns every repository:tag running anywhere, once each.
//
// Digest-less containers are included here, unlike in DistinctContainerImages:
// a scan needs a digest to fetch bytes, but a registry check only needs the
// repository and tag, and an unpinned container is precisely the one most likely
// to have drifted from its tag.
func (s *Store) TrackedImages(ctx context.Context) ([]TrackedImage, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT c->>'repository'            AS repository,
		       COALESCE(c->>'tag', '')     AS tag,
		       -- One tag can be running at several digests across the fleet
		       -- mid-rollout. max() picks one deterministically rather than
		       -- duplicating the row; the per-host digests stay in inventory.
		       MAX(COALESCE(c->>'digest', '')) AS digest
		FROM host_inventory hi,
		     LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
		WHERE COALESCE(c->>'repository','') <> ''
		  AND COALESCE(c->>'tag','') <> ''
		GROUP BY 1, 2
		ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrackedImage{}
	for rows.Next() {
		var t TrackedImage
		if err := rows.Scan(&t.Repository, &t.Tag, &t.Digest); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UpsertImageUpdate records what the registry said.
func (s *Store) UpsertImageUpdate(ctx context.Context, in ImageUpdate) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO container_image_updates
		    (repository, tag, current_digest, latest_tag, note, error, declared, status, checked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (repository, tag) DO UPDATE SET
		    current_digest = EXCLUDED.current_digest,
		    latest_tag     = EXCLUDED.latest_tag,
		    note           = EXCLUDED.note,
		    error          = EXCLUDED.error,
		    declared       = EXCLUDED.declared,
		    status         = EXCLUDED.status,
		    checked_at     = now()`,
		in.Repository, in.Tag, in.Digest, in.LatestTag, in.Note, in.Error, in.Declared, in.Status)
	return err
}

// ImageUpdates returns every recorded check.
func (s *Store) ImageUpdates(ctx context.Context) ([]ImageUpdate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT repository, tag, current_digest, latest_tag, note, error, declared, status, checked_at
		FROM container_image_updates
		ORDER BY repository, tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ImageUpdate{}
	for rows.Next() {
		var u ImageUpdate
		if err := rows.Scan(&u.Repository, &u.Tag, &u.Digest, &u.LatestTag,
			&u.Note, &u.Error, &u.Declared, &u.Status, &u.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// StaleImageChecks narrows a list of tracked images to those worth asking a
// registry about.
//
// Registries rate limit anonymous clients hard -- Docker Hub counts manifest
// requests per IP -- and a fleet running a hundred distinct images would burn
// that budget on images checked an hour ago. An image whose last check ERRORED is
// deliberately treated as stale so a transient failure retries, but on the same
// interval as everything else rather than in a tight loop.
func (s *Store) StaleImageChecks(ctx context.Context, imgs []TrackedImage, maxAge time.Duration) ([]TrackedImage, error) {
	if len(imgs) == 0 {
		return nil, nil
	}
	rows, err := s.pool.Query(ctx, `
		SELECT repository, tag FROM container_image_updates
		WHERE checked_at > now() - $1::interval
		  AND error = ''
		  -- A row with no digest concluded "built locally, nothing to ask about".
		  -- That conclusion is drawn from what the FLEET reported at the time, and
		  -- the fleet changes: forty images were marked built-locally during a
		  -- window when digests were not being collected at all, and the freshness
		  -- rule then held that verdict for twelve hours after the digests arrived.
		  --
		  -- Re-checking them is nearly free: an image with no digest is answered
		  -- without asking a registry anything, so this costs one row read per pass
		  -- for the genuinely local ones and corrects the rest immediately.
		  AND current_digest <> ''`,
		maxAge.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fresh := map[string]bool{}
	for rows.Next() {
		var repo, tag string
		if err := rows.Scan(&repo, &tag); err != nil {
			return nil, err
		}
		fresh[repo+":"+tag] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := []TrackedImage{}
	for _, img := range imgs {
		if !fresh[img.Repository+":"+img.Tag] {
			out = append(out, img)
		}
	}
	return out, nil
}

// PruneImageUpdates drops rows for images nothing runs any more.
//
// Without this the table only grows, and the UI would offer an upgrade for a
// container that was removed from the fleet months ago.
func (s *Store) PruneImageUpdates(ctx context.Context, keep []TrackedImage) error {
	repos := make([]string, 0, len(keep))
	tags := make([]string, 0, len(keep))
	for _, k := range keep {
		repos = append(repos, k.Repository)
		tags = append(tags, k.Tag)
	}
	// An empty keep-set means no host reports any container, which is far more
	// likely to be a collection outage than a fleet that genuinely runs nothing.
	// Deleting everything on that signal would throw away the history and then
	// re-fetch it all from the registry on recovery.
	if len(repos) == 0 {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
		DELETE FROM container_image_updates u
		WHERE NOT EXISTS (
		    SELECT 1 FROM unnest($1::text[], $2::text[]) AS k(repository, tag)
		    WHERE k.repository = u.repository AND k.tag = u.tag)`,
		repos, tags)
	return err
}

// ImageUpdateHost is one host running an image, and the digest it runs it at.
type ImageUpdateHost struct {
	HostID    string `json:"hostId"`
	Hostname  string `json:"hostname"`
	Digest    string `json:"digest,omitempty"`
	Container string `json:"container,omitempty"`
	// Stale is true when this host's digest differs from what the tag points at
	// now. Per host, not per image: mid-rollout some hosts have the new bytes and
	// some do not, and an image-level flag would hide exactly that.
	Stale bool `json:"stale"`
	// Protected means this container is part of Provenance itself, on this host.
	// It is shown — what the instance runs, and what is wrong with those images,
	// is exactly what an operator should see — but it is never offered for a
	// rollout: this application is upgraded by signed bundle.
	Protected bool `json:"protected,omitempty"`
}

// ImageUpdateRow is one repository:tag with what the registry said and who runs it.
type ImageUpdateRow struct {
	ImageUpdate
	Hosts []ImageUpdateHost `json:"hosts"`
}

// ImageUpdatesWithHosts returns every checked image together with the hosts
// running it.
//
// The hosts are the point. "nginx:1.24 has 1.27 available" is not actionable on
// its own -- an operator needs to know which machines that is true of before they
// can decide anything, and looking it up per image is the work this avoids.
func (s *Store) ImageUpdatesWithHosts(ctx context.Context, selfProject string) ([]ImageUpdateRow, error) {
	// Driven by what the fleet RUNS, not by what has been checked.
	//
	// Starting from the checked rows meant an image only appeared here once a
	// registry had been asked about it — and the check runs every twelve hours. A
	// host whose containers had just become visible contributed nothing to this
	// screen for most of a day, with no row saying so: twenty-four containers on
	// a host, and a page that showed none of them. "We have not asked yet" and
	// "there is nothing there" are different, and this page is the one place that
	// distinction is the whole point.
	tracked, err := s.TrackedImages(ctx)
	if err != nil {
		return nil, err
	}
	checked, err := s.ImageUpdates(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `
		SELECT c->>'repository', COALESCE(c->>'tag',''), h.id::text, h.hostname,
		       COALESCE(c->>'digest',''), COALESCE(c->>'name',''),
		       COALESCE(c->>'composeProject',''), COALESCE(c->>'image','')
		FROM host_inventory hi
		JOIN hosts h ON h.id = hi.host_id,
		     LATERAL jsonb_array_elements(COALESCE(hi.containers, '[]'::jsonb)) AS c
		WHERE COALESCE(c->>'repository','') <> ''
		  AND COALESCE(c->>'tag','') <> ''
		ORDER BY h.hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byImage := map[string][]ImageUpdateHost{}
	for rows.Next() {
		var repo, tag, project, image string
		var hh ImageUpdateHost
		if err := rows.Scan(&repo, &tag, &hh.HostID, &hh.Hostname, &hh.Digest, &hh.Container,
			&project, &image); err != nil {
			return nil, err
		}
		hh.Protected = selfProject != "" &&
			(project == selfProject || strings.HasPrefix(image, selfProject+"-"))
		byImage[repo+":"+tag] = append(byImage[repo+":"+tag], hh)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return assembleImageRows(tracked, checked, byImage), nil
}

// assembleImageRows decides which rows an operator is shown, and therefore which
// ones they can act on.
//
// Separated from the queries because it is the decision rather than the
// plumbing, and it got that decision wrong in a way no query test would have
// caught: the list was built only from what the fleet RUNS, which silently
// dropped every row that could be applied.
func assembleImageRows(tracked []TrackedImage, checked []ImageUpdate,
	byImage map[string][]ImageUpdateHost) []ImageUpdateRow {
	byKey := make(map[string]ImageUpdate, len(checked))
	for _, u := range checked {
		byKey[u.Repository+":"+u.Tag] = u
	}

	out := make([]ImageUpdateRow, 0, len(tracked))
	for _, t := range tracked {
		key := t.Repository + ":" + t.Tag
		u, ok := byKey[key]
		if !ok {
			// Never asked about. CheckedAt stays zero, which is how the client
			// tells this apart from a check that came back with nothing to report.
			u = ImageUpdate{Repository: t.Repository, Tag: t.Tag}
		}
		hosts := byImage[key]
		if hosts == nil {
			hosts = []ImageUpdateHost{}
		}
		for i := range hosts {
			// Only a host with a known digest can be called stale. An unknown
			// digest is unknown, not old -- claiming otherwise would show a host
			// as needing an update nobody can confirm it needs.
			hosts[i].Stale = hosts[i].Digest != "" && u.Digest != "" &&
				hosts[i].Digest != u.Digest
		}
		out = append(out, ImageUpdateRow{ImageUpdate: u, Hosts: hosts})
	}

	// Then the rows for tags a compose file NAMES but nothing is running yet.
	//
	// A container on :latest whose compose names v1.6.0-ls356 produces two rows,
	// and they behave in opposite ways. Rolling out the :latest one can only
	// skip: the host's compose has moved past :latest, so the image is
	// superseded and the container is never recreated, and the row reports
	// "rebuilt" again on the next check, forever. Rolling out the declared one
	// rewrites the file, recreates the container, and is what finally moves it
	// off :latest.
	//
	// Six services were in that state and the actionable row for every one of
	// them was invisible here -- so the rebuild row was the only thing on offer,
	// was rolled out, completed successfully, and changed nothing.
	//
	// The hosts are those running the REPOSITORY at any tag, which is the same
	// rule the rollout engine applies when deciding whether a declared tag counts
	// as one a host runs. What this screen offers and what a rollout will do
	// cannot disagree.
	byRepo := map[string][]ImageUpdateHost{}
	for key, hosts := range byImage {
		colon := strings.LastIndex(key, ":")
		if colon < 0 {
			continue
		}
		byRepo[key[:colon]] = append(byRepo[key[:colon]], hosts...)
	}
	for _, u := range checked {
		if !u.Declared {
			continue
		}
		if _, running := byImage[u.Repository+":"+u.Tag]; running {
			continue // already emitted above, from the running list
		}
		hosts := byRepo[u.Repository]
		if len(hosts) == 0 {
			continue // nothing runs this repository; the next check prunes it
		}
		// Deliberately NOT marked stale. Stale compares the digest a host is
		// running against the one behind THIS tag, and a host that is not running
		// this tag has no answer to that -- calling it old would invent one.
		copied := make([]ImageUpdateHost, len(hosts))
		copy(copied, hosts)
		for i := range copied {
			copied[i].Stale = false
		}
		out = append(out, ImageUpdateRow{ImageUpdate: u, Hosts: copied})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Repository != out[j].Repository {
			return out[i].Repository < out[j].Repository
		}
		return out[i].Tag < out[j].Tag
	})
	return out
}

// HostContainers returns what one host reported running.
//
// For the rollout engine: a container's own compose labels say which project and
// service it belongs to and where that project lives, which is what lets an image
// be updated in place without Provenance holding a copy of its compose file.
func (s *Store) HostContainers(ctx context.Context, hostID uuid.UUID) ([]models.Container, error) {
	var raw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT COALESCE(containers, jsonb_build_array())
		FROM host_inventory WHERE host_id = $1`, hostID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	out := []models.Container{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// EnabledStackComposes returns the compose text of every enabled stack.
//
// For the registry check, which needs the tags an operator has CHOSEN and not
// only the ones that happen to be running.
func (s *Store) EnabledStackComposes(ctx context.Context) ([]string, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT compose FROM container_stacks WHERE enabled AND COALESCE(compose,'') <> ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LastCheckedAt returns when each recorded image was last asked about.
//
// For ordering a pass. See leastRecentlyCheckedFirst: the batch cap means SOME
// images wait, and which ones wait must not be decided by where they happen to
// sit in a list.
func (s *Store) LastCheckedAt(ctx context.Context) (map[string]time.Time, error) {
	rows, err := s.pool.Query(ctx, `SELECT repository, tag, checked_at FROM container_image_updates`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var repo, tag string
		var at time.Time
		if err := rows.Scan(&repo, &tag, &at); err != nil {
			return nil, err
		}
		out[repo+":"+tag] = at
	}
	return out, rows.Err()
}

// Image check verdicts, as values rather than prose. See ImageUpdate.Status.
const (
	ImageStatusUpdate      = "update"      // a newer tag of the same shape exists
	ImageStatusMoved       = "moved"       // same tag, different bytes
	ImageStatusCurrent     = "current"     // checked; nothing newer of the same shape
	ImageStatusUnorderable = "unorderable" // no tag in the repository can be ordered against this one
	ImageStatusLocal       = "local"       // built on the host; never in a registry
	ImageStatusUnavailable = "unavailable" // the registry would not answer in full
)

// CachedTags returns a repository's cached tag listing when it is fresh enough.
func (s *Store) CachedTags(ctx context.Context, repo string, maxAge time.Duration) ([]string, bool, bool) {
	var raw []byte
	var complete bool
	err := s.pool.QueryRow(ctx, `
		SELECT tags, complete FROM registry_tag_cache
		WHERE repository = $1 AND fetched_at > now() - $2::interval`,
		repo, maxAge.String()).Scan(&raw, &complete)
	if err != nil {
		return nil, false, false
	}
	var tags []string
	if json.Unmarshal(raw, &tags) != nil {
		return nil, false, false
	}
	return tags, complete, true
}

// AnyCachedTags returns a repository's cached listing at any age.
//
// For a registry that has just refused to answer: a stale list beats no list,
// and "here is what was published as of this morning" is a better answer than
// "could not check" against an image that is fine.
func (s *Store) AnyCachedTags(ctx context.Context, repo string) ([]string, bool, bool) {
	return s.CachedTags(ctx, repo, 365*24*time.Hour)
}

// PutCachedTags records a repository's tag listing.
func (s *Store) PutCachedTags(ctx context.Context, repo string, tags []string, complete bool) error {
	raw, err := json.Marshal(tags)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO registry_tag_cache (repository, tags, complete, fetched_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (repository) DO UPDATE SET
		    tags = EXCLUDED.tags, complete = EXCLUDED.complete, fetched_at = now()`,
		repo, raw, complete)
	return err
}
