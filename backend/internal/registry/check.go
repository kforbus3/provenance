package registry

import (
	"context"
	"log/slog"
	"time"

	"github.com/kforbus3/provenance/backend/internal/composefile"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// How long a check stays good.
//
// Twelve hours, not one. A tag moving is not an emergency -- it is a thing an
// operator decides about during working hours -- and every check is a manifest
// request against a rate limit that Docker Hub applies per IP across the whole
// fleet's worth of images.
const checkMaxAge = 12 * time.Hour

// How many images to ask about in one pass.
//
// Each image costs at least one manifest HEAD, plus a tag listing when a digest
// changed. Anonymous Docker Hub allows a low hundreds of manifest requests per
// six hours; a pass that makes steady progress beats one that gets refused
// halfway and leaves the table half-updated with errors that look like outages.
const checkBatch = 40

// Store is the slice of the store this package needs. An interface rather than
// *store.Store so the check loop -- which decides what an operator is told about
// every image the fleet runs -- can be tested against a fake instead of only
// against a live database and a live registry.
type Store interface {
	TrackedImages(ctx context.Context) ([]store.TrackedImage, error)
	EnabledStackComposes(ctx context.Context) ([]string, error)
	StaleImageChecks(ctx context.Context, imgs []store.TrackedImage, maxAge time.Duration) ([]store.TrackedImage, error)
	UpsertImageUpdate(ctx context.Context, in store.ImageUpdate) error
	PruneImageUpdates(ctx context.Context, keep []store.TrackedImage) error
}

// Checker asks registries what is available for the images the fleet runs.
type Checker struct {
	store  Store
	client *Client
	log    *slog.Logger
}

func NewChecker(st Store, log *slog.Logger) *Checker {
	return &Checker{store: st, client: New(), log: log}
}

// Check runs one pass. Returns how many images were checked and how many failed.
//
// Never fatal. A registry that will not answer -- private, rate limited, offline
// -- is recorded against that image and the pass continues; one unreachable
// registry must not stop the fleet from learning about every other image.
func (c *Checker) Check(ctx context.Context) (checked, failed int) {
	checked, failed, _ = c.check(ctx, false)
	return checked, failed
}

// CheckNow ignores the freshness window.
//
// The window exists to stop the scheduled sweep re-asking registries about
// answers it already has. It has no business overriding somebody who has just
// pressed a button: they are asking because they believe the answer has changed,
// which is usually because they just changed it.
//
// The batch cap still applies. That one is not about staleness but about a
// registry's rate limit, which does not care why the request was made — so a
// forced pass reports how many images are still waiting rather than quietly
// doing part of the job.
func (c *Checker) CheckNow(ctx context.Context) (checked, failed, remaining int) {
	return c.check(ctx, true)
}

func (c *Checker) check(ctx context.Context, force bool) (checked, failed, remaining int) {
	tracked, err := c.store.TrackedImages(ctx)
	if err != nil {
		c.log.Warn("image check: listing tracked images", "err", err)
		return 0, 0, 0
	}
	if len(tracked) == 0 {
		return 0, 0, 0
	}
	// What the operator CHOSE, alongside what happens to be running. See
	// declaredExtras: a pinned service that has not been recreated yet is only
	// ever asked about under the tag it is still running.
	composes, err := c.store.EnabledStackComposes(ctx)
	if err != nil {
		c.log.Warn("image check: listing stack composes", "err", err)
	} else {
		tracked = append(tracked, declaredExtras(tracked, composes)...)
	}

	// Drop rows for images nothing runs any more before checking, so the pass
	// budget is not spent on an image that was removed from the fleet.
	//
	// Pruning takes the combined list, or every declared row written by the pass
	// before would be deleted by the pass after it.
	if err := c.store.PruneImageUpdates(ctx, tracked); err != nil {
		c.log.Warn("image check: pruning", "err", err)
	}

	stale := tracked
	if !force {
		var err error
		stale, err = c.store.StaleImageChecks(ctx, tracked, checkMaxAge)
		if err != nil {
			c.log.Warn("image check: selecting stale", "err", err)
			return 0, 0, 0
		}
	}
	if len(stale) > checkBatch {
		remaining = len(stale) - checkBatch
		stale = stale[:checkBatch]
	}

	for _, img := range stale {
		if ctx.Err() != nil {
			return checked, failed, remaining
		}
		rec := c.checkOne(ctx, img)
		if rec.Error != "" {
			failed++
		} else {
			checked++
		}
		if err := c.store.UpsertImageUpdate(ctx, rec); err != nil {
			c.log.Warn("image check: saving result",
				"repository", img.Repository, "tag", img.Tag, "err", err)
		}
	}
	if checked > 0 || failed > 0 {
		c.log.Info("container image check", "checked", checked, "failed", failed,
			"stale", len(stale), "tracked", len(tracked), "forced", force,
			"remaining", remaining)
	}
	return checked, failed, remaining
}

// checkOne asks about a single repository:tag.
func (c *Checker) checkOne(ctx context.Context, img store.TrackedImage) store.ImageUpdate {
	rec := store.ImageUpdate{Repository: img.Repository, Tag: img.Tag}

	// An image with no repository digest was never pulled from a registry. Docker
	// records RepoDigests only for images it fetched, so a locally built one --
	// this product's own containers among them -- has none.
	//
	// Asking a registry about it is worse than useless: a bare name resolves to
	// Docker Hub, "fleet-terminal-backend" is not a repository there, and Hub
	// answers 401 for repositories that do not exist. That surfaces as "this
	// registry needs credentials", which sends an operator to configure
	// credentials that cannot help, for an image that will never be in a registry
	// at all. On a host running this product it was ten rows of that out of
	// thirteen.
	//
	// The digest is the MAX across every host running the image, so this is only
	// reached when NO host has one.
	if img.Digest == "" {
		rec.Note = "built locally — no registry digest on any host running it, so there is nothing to compare against"
		return rec
	}

	digest, err := c.client.Digest(ctx, img.Repository, img.Tag)
	if err != nil {
		rec.Error = truncate(err.Error(), 400)
		return rec
	}
	rec.Digest = digest

	// "latest" and friends are not version tags. Listing a repository's tags to
	// find something newer than "latest" would compare it against every unrelated
	// tag in the repository and find no ordering, so the digest comparison above
	// is the whole answer for these -- and it is a good one: a moved "latest" IS
	// the update.
	if !looksVersioned(img.Tag) {
		if img.Declared {
			rec.Note = drifted(img)
			return rec
		}
		if img.Digest != "" && digest != img.Digest {
			rec.Note = "tag moved: this host is running an older build of " + img.Tag
		}
		return rec
	}

	tags, err := c.client.Tags(ctx, img.Repository)
	if err != nil {
		// The digest answer is still good and worth keeping. Record the tag
		// listing failure as a note rather than an error so the row does not read
		// as "this image could not be checked at all" -- some registries allow
		// manifest reads but not catalog listing.
		rec.Note = "could not list tags: " + truncate(err.Error(), 200)
		if img.Digest != "" && digest != img.Digest {
			rec.Note = "tag moved since this host pulled it; " + rec.Note
		}
		return rec
	}

	newest, reason := Newest(img.Tag, tags)
	rec.LatestTag = newest
	rec.Note = reason
	if img.Declared {
		// The digest comparison below asks "did the bytes behind the tag this
		// host PULLED change". For a declared tag the host has not pulled it, so
		// there is nothing truthful to say about a rebuild -- but the drift
		// itself is worth saying, and it is the reason the version above was
		// findable at all.
		if newest == "" {
			rec.Note = drifted(img)
		} else {
			rec.Note = reason + "; " + drifted(img)
		}
		return rec
	}
	if newest == "" && img.Digest != "" && digest != img.Digest {
		// No newer version tag, but the tag this host runs does not point where
		// the host's copy came from. A rebuild of the same version -- a base
		// image security update, most often -- looks exactly like this, and it is
		// the case a version-number comparison alone would miss entirely.
		rec.Note = "tag moved: rebuilt at the same version"
	}
	return rec
}

// looksVersioned reports whether a tag is one a version ordering can say
// anything about. A tag with no digits in it -- latest, stable, main, edge -- is
// a moving pointer, not a version.
func looksVersioned(tag string) bool {
	_, ok := ParseVersion(tag)
	return ok
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// declaredExtras returns the tags a managed stack names that nothing is running.
//
// A compose file pinned to bazarr:v1.6.0-ls356 whose container is still on
// :latest -- the state every service is in between being pinned and being
// recreated -- is otherwise only ever asked about under :latest. Against a
// moving tag the only available answer is "latest moved again", so the version
// the operator actually chose is never compared against the registry and a real
// upgrade waiting there stays invisible. Thirteen services across two hosts were
// in exactly that state.
//
// Added rather than substituted. The running tag is still a true fact about the
// fleet, and another host may legitimately be running that repository unpinned;
// dropping its row would hide a moved tag that does matter. These rows answer a
// different question, so they are carried as different rows.
//
// The digest comes from the running container because it is the only one the
// fleet has -- which is also why checkOne says nothing about rebuilds for these.
func declaredExtras(tracked []store.TrackedImage, composes []string) []store.TrackedImage {
	// What is already being asked about, so a declared tag that some host does
	// run is not asked about twice.
	have := map[string]bool{}
	running := map[string]store.TrackedImage{}
	for _, t := range tracked {
		have[t.Repository+":"+t.Tag] = true
		// One row per repository is enough to borrow a digest from; which host it
		// came from does not change the question being asked.
		if _, ok := running[t.Repository]; !ok && t.Digest != "" {
			running[t.Repository] = t
		}
	}

	var out []store.TrackedImage
	added := map[string]bool{}
	for _, compose := range composes {
		for _, ref := range composefile.Images(compose) {
			key := ref.Repository + ":" + ref.Tag
			if have[key] || added[key] {
				continue
			}
			// Only for a repository the fleet actually runs. A compose file may
			// name a service that is scaled to zero or commented out of the
			// running project, and asking a registry about an image nothing runs
			// spends a rate-limited request on nobody's behalf.
			run, ok := running[ref.Repository]
			if !ok {
				continue
			}
			added[key] = true
			out = append(out, store.TrackedImage{
				Repository: ref.Repository,
				Tag:        ref.Tag,
				Digest:     run.Digest,
				Declared:   true,
				RunningTag: run.Tag,
			})
		}
	}
	return out
}

// drifted states the gap between what a compose file names and what is running.
func drifted(img store.TrackedImage) string {
	if img.RunningTag == "" || img.RunningTag == img.Tag {
		return "named by a compose file; no container is running this tag yet"
	}
	return "a compose file names " + img.Tag + " but the container is still running " +
		img.RunningTag + " — deploy the stack to apply it"
}
