package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// supersededImages decides which stack image tags an upgrade has made redundant.
//
// This product is installed once and upgraded by bundle from then on, so anything
// an install leaves behind is left behind forever -- nobody is going to run
// `docker image prune` on an appliance. Every bundle since the first had been
// doing exactly that: a fleet upgraded from 0.70 onwards held 152 stack images
// across five components, 49 tags of the backend alone, and 9.2GB of them. The
// disk filled, and the fix looked like a housekeeping chore rather than a defect
// in the installer.
//
// Two things are kept, and only two:
//
//   - the version just installed, because it is running;
//   - anything tagged :rollback, because that is the anchor the updater reverts
//     to. It is a separate tag applied to the previous images before the swap
//     (step 4 of apply), which is why the PREVIOUS VERSION's own tag is not
//     special and does not need keeping -- the rollback path never looks it up.
//
// Everything else is a tag for a version this machine has already moved past.
//
// Only images this product publishes are considered: the prefix is matched
// exactly and the component must be one the bundle ships. A daemon shared with
// anything else -- and on an imaging deployment it is shared with the image
// builder and the PXE server -- must not have its images touched by an upgrade.
func supersededImages(tags []string, projectPrefix, keepVersion string, components []string) []string {
	comp := map[string]bool{}
	for _, c := range components {
		comp[c] = true
	}
	var out []string
	for _, t := range tags {
		repo, tag, ok := strings.Cut(t, ":")
		if !ok || tag == "" {
			continue
		}
		name, found := strings.CutPrefix(repo, projectPrefix)
		if !found || !comp[name] {
			continue
		}
		// The rollback anchor and the running version stay. "<none>" is a dangling
		// layer rather than a version and is left to Docker's own prune: removing
		// one by reference is not what that string means.
		if tag == "rollback" || tag == keepVersion || tag == "<none>" || tag == "latest" {
			continue
		}
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// pruneSuperseded removes the image tags an upgrade has made redundant.
//
// Best-effort by construction, and called only after the upgrade is already
// recorded as a success: an upgrade that worked must never be reported as failed
// because a cleanup did not. Docker refuses to remove an image a container is
// using, which is the backstop if the keep rules above are ever wrong.
func (u *Updater) pruneSuperseded(ctx context.Context, keepVersion string, components []string) {
	tags, err := u.docker.ListImageTags(ctx)
	if err != nil {
		u.set("success", "note: could not list images to clean up ("+err.Error()+")")
		return
	}
	stale := supersededImages(tags, u.cfg.Project+"-", keepVersion, components)
	if len(stale) == 0 {
		return
	}
	removed := 0
	for _, ref := range stale {
		if err := u.docker.RemoveImage(ctx, ref); err == nil {
			removed++
		}
	}
	u.set("success", fmt.Sprintf("cleaned up %d superseded image(s) of %d; kept %s and :rollback",
		removed, len(stale), keepVersion))
}

// componentNames is the set of components a bundle carried, as a sorted slice.
func componentNames(comps map[string]bool) []string {
	out := make([]string, 0, len(comps))
	for c := range comps {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}
