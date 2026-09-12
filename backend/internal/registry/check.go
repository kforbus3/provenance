package registry

import (
	"context"
	"log/slog"
	"time"

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
	tracked, err := c.store.TrackedImages(ctx)
	if err != nil {
		c.log.Warn("image check: listing tracked images", "err", err)
		return 0, 0
	}
	if len(tracked) == 0 {
		return 0, 0
	}
	// Drop rows for images nothing runs any more before checking, so the pass
	// budget is not spent on an image that was removed from the fleet.
	if err := c.store.PruneImageUpdates(ctx, tracked); err != nil {
		c.log.Warn("image check: pruning", "err", err)
	}

	stale, err := c.store.StaleImageChecks(ctx, tracked, checkMaxAge)
	if err != nil {
		c.log.Warn("image check: selecting stale", "err", err)
		return 0, 0
	}
	if len(stale) > checkBatch {
		stale = stale[:checkBatch]
	}

	for _, img := range stale {
		if ctx.Err() != nil {
			return checked, failed
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
			"stale", len(stale), "tracked", len(tracked))
	}
	return checked, failed
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
