package containerupdate

import (
	"strings"

	"github.com/kforbus3/provenance/backend/internal/composefile"
)

// RewriteImageTag changes every `image:` entry naming repo:from so it names
// repo:to, and reports how many it changed.
//
// Line-based rather than a YAML round-trip, and deliberately so. Parsing a
// compose file and re-emitting it rewrites the WHOLE file: comments vanish,
// anchors expand, key order changes, and quoting style is normalised. The result
// is a diff an operator cannot review, attached to an update they are being asked
// to approve. This changes the bytes it was asked to change and nothing else.
//
// Nothing is guessed. A line is rewritten only when its image value's repository
// and tag both match exactly, so:
//
//   - nginx-extras:1.24 is untouched when rewriting nginx:1.24
//   - ghcr.io/nginx:1.24 is untouched when rewriting nginx:1.24
//   - nginx:1.24-alpine is untouched when rewriting nginx:1.24
//
// An unmatched file yields 0, and the caller must treat that as "this stack does
// not contain what I thought it did" rather than deploying an unchanged file and
// counting it as an update applied.
func RewriteImageTag(compose, repo, from, to string) (string, int) {
	if repo == "" || from == "" || to == "" {
		return compose, 0
	}
	lines := strings.Split(compose, "\n")
	changed := 0
	for i, line := range lines {
		key, value, ok := composefile.SplitImageLine(line)
		if !ok {
			continue
		}
		ref, trailer := composefile.SplitTrailingComment(value)
		// The whitespace between the value and a trailing comment is part of the
		// operator's formatting, not part of the reference. Trimming it for
		// parsing and then not putting it back jams the comment against the tag.
		gap := ref[len(strings.TrimRight(ref, " \t")):]
		quote, bare := composefile.Unquote(strings.TrimSpace(ref))

		// A digest pin travels with the tag. Dropping it here is intentional: the
		// pin names the OLD bytes, and keeping it would produce repo:new@sha256
		// of the old image -- a reference that either fails to pull or silently
		// pulls the old image under the new tag's name.
		name := bare
		if at := strings.Index(name, "@"); at >= 0 {
			name = name[:at]
		}
		r, t, ok := composefile.SplitRef(name)
		if !ok || r != repo || t != from {
			continue
		}
		lines[i] = key + quote + repo + ":" + to + quote + gap + trailer
		changed++
	}
	if changed == 0 {
		return compose, 0
	}
	return strings.Join(lines, "\n"), changed
}

// ReferencesImage reports whether a compose file names repo:tag as an image.
//
// The same matching as RewriteImageTag, so "does this stack own the image" and
// "which lines would change" can never disagree. Needed on its own for a
// digest-only update -- the same tag rebuilt -- where the right rewrite is no
// rewrite at all and a count of zero changed lines does not mean the stack is
// unrelated.
func ReferencesImage(compose, repo, tag string) bool {
	if repo == "" || tag == "" {
		return false
	}
	for _, line := range strings.Split(compose, "\n") {
		_, value, ok := composefile.SplitImageLine(line)
		if !ok {
			continue
		}
		ref, _ := composefile.SplitTrailingComment(value)
		_, bare := composefile.Unquote(strings.TrimSpace(ref))
		if at := strings.Index(bare, "@"); at >= 0 {
			bare = bare[:at]
		}
		if r, t, ok := composefile.SplitRef(bare); ok && r == repo && t == tag {
			return true
		}
	}
	return false
}

// composeOwnsImage reports whether a compose file is the one this container came
// from, for an update moving `from` to `to`.
//
// Either tag counts. Asking only about `from` was wrong in a way that a live
// rollout kept hitting: a compose file edited ahead of its containers — by hand,
// or by an earlier attempt that wrote the file and failed before deploying —
// already names `to` while the container still runs `from`, because nobody has
// run `up -d` since.
//
//	compose says     curlimages/curl:8.22.0
//	container runs   curlimages/curl:8.10.1
//	rollout wants    8.10.1 -> 8.22.0
//
// Refusing there concluded "this is not the project this container came from",
// which is false. It is the project; it is simply already where the rollout wants
// to get to, and the work left is to deploy it. Every partially-applied change is
// in exactly this state, so refusing made the rollout unable to finish the job it
// had itself half-done.
func composeOwnsImage(compose, repo, from, to string) bool {
	return ReferencesImage(compose, repo, from) || ReferencesImage(compose, repo, to)
}

// composeSupersedes reports that a compose file names this repository, but at
// neither the tag the rollout is moving from nor the one it is moving to.
//
// The host has moved past this image. Somebody re-pinned the service between the
// rollout being created and reaching this host — which is ordinary on a fleet
// anybody is actively working on, and was produced here by pinning :latest to a
// version while a rollout for :latest was queued.
//
// Attempting it anyway deploys correctly and then fails verification, because the
// tag the rollout is looking for is no longer in the file:
//
//	qdrant/qdrant:latest → latest: deployed, but no container on this host
//	is running qdrant/qdrant:latest
//
// That reads as a broken rollout. It is a rollout whose premise expired, which is
// a different thing and deserves to be skipped rather than failed.
func composeSupersedes(compose, repo, from, to string) bool {
	if !mentionsRepository(compose, repo) {
		return false
	}
	return !ReferencesImage(compose, repo, from) && !ReferencesImage(compose, repo, to)
}

// mentionsRepository reports whether any image line names this repository, at
// whatever tag.
func mentionsRepository(compose, repo string) bool {
	if repo == "" {
		return false
	}
	for _, line := range strings.Split(compose, "\n") {
		_, value, ok := composefile.SplitImageLine(line)
		if !ok {
			continue
		}
		ref, _ := composefile.SplitTrailingComment(value)
		_, bare := composefile.Unquote(strings.TrimSpace(ref))
		if at := strings.Index(bare, "@"); at >= 0 {
			bare = bare[:at]
		}
		if r, _, ok := composefile.SplitRef(bare); ok && r == repo {
			return true
		}
	}
	return false
}
