package containerupdate

import (
	"strings"
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
		key, value, ok := splitImageLine(line)
		if !ok {
			continue
		}
		ref, trailer := splitTrailingComment(value)
		// The whitespace between the value and a trailing comment is part of the
		// operator's formatting, not part of the reference. Trimming it for
		// parsing and then not putting it back jams the comment against the tag.
		gap := ref[len(strings.TrimRight(ref, " \t")):]
		quote, bare := unquote(strings.TrimSpace(ref))

		// A digest pin travels with the tag. Dropping it here is intentional: the
		// pin names the OLD bytes, and keeping it would produce repo:new@sha256
		// of the old image -- a reference that either fails to pull or silently
		// pulls the old image under the new tag's name.
		name := bare
		if at := strings.Index(name, "@"); at >= 0 {
			name = name[:at]
		}
		r, t, ok := splitRef(name)
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

// splitImageLine splits "    image: nginx:1.24" into its key part (through the
// colon and following space) and its value.
//
// Only a line whose key is exactly `image` counts. A line like
// `command: echo image: x` has no key at position zero-after-indent and is
// skipped, and so is `x-my-image: nginx:1.24`, which is not a compose image key.
func splitImageLine(line string) (key, value string, ok bool) {
	trimmed := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmed)]
	// A list item -- "- image: x" -- is not a compose image key either, but a
	// leading dash is part of ordinary indentation in other contexts; requiring
	// the key to start the content is enough.
	rest, found := strings.CutPrefix(trimmed, "image:")
	if !found {
		return "", "", false
	}
	// "image:" must be followed by whitespace or nothing. Without this,
	// "image::" or a key like "image:foo" would match.
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", "", false
	}
	spaces := len(rest) - len(strings.TrimLeft(rest, " \t"))
	return indent + "image:" + rest[:spaces], rest[spaces:], true
}

// splitTrailingComment separates a value from a trailing YAML comment, keeping
// the comment so an operator's note survives the rewrite.
//
// A '#' only starts a comment when preceded by whitespace, which is what keeps
// a digest-pinned reference or a URL fragment from being cut in half.
func splitTrailingComment(value string) (ref, trailer string) {
	for i := 0; i < len(value); i++ {
		if value[i] != '#' {
			continue
		}
		if i == 0 || value[i-1] == ' ' || value[i-1] == '\t' {
			return value[:i], value[i:]
		}
	}
	return value, ""
}

// unquote strips a matching pair of surrounding quotes, returning the quote
// character used so the rewrite can put back what was there.
func unquote(s string) (quote, bare string) {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return string(s[0]), s[1 : len(s)-1]
		}
	}
	return "", s
}

// splitRef splits repository:tag.
//
// The colon is found after the last slash, because a registry may carry a port:
// splitting "registry.example.com:5000/app" on the first colon yields a
// repository of "registry.example.com" and a tag of "5000/app", which is wrong
// in a way nobody notices until it is their registry.
func splitRef(ref string) (repo, tag string, ok bool) {
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon <= slash {
		return "", "", false // no tag
	}
	return ref[:colon], ref[colon+1:], true
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
		_, value, ok := splitImageLine(line)
		if !ok {
			continue
		}
		ref, _ := splitTrailingComment(value)
		_, bare := unquote(strings.TrimSpace(ref))
		if at := strings.Index(bare, "@"); at >= 0 {
			bare = bare[:at]
		}
		if r, t, ok := splitRef(bare); ok && r == repo && t == tag {
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
