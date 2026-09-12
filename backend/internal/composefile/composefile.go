// Package composefile parses the image references out of a docker-compose file.
//
// One parser, deliberately. The rollout rewriter and the registry checker both
// have to answer "which image does this file name, at which tag", and two
// implementations of that question drift apart silently: the rewriter would edit
// a line the checker never counted, or the checker would offer an update for a
// reference the rewriter cannot find. Both read from here.
//
// This is not a YAML parser and does not try to be. A compose file is edited by
// hand and read back by people, so the rewriter works line by line to preserve
// quoting, comments and ordering exactly; the parsing primitives it needs are
// the same ones the checker needs, so they live together.
package composefile

import "strings"

// Ref is one image reference found in a compose file.
type Ref struct {
	Repository string
	Tag        string
}

// Images returns every repository:tag the file names, in file order, once each.
//
// A reference with no tag is skipped: "nginx" means "nginx:latest" to Docker,
// but writing that assumption in here would have the checker report an update
// for a tag the file does not contain and the rewriter cannot edit.
func Images(compose string) []Ref {
	var out []Ref
	seen := map[string]bool{}
	for _, line := range strings.Split(compose, "\n") {
		_, value, ok := SplitImageLine(line)
		if !ok {
			continue
		}
		ref, _ := SplitTrailingComment(value)
		_, bare := Unquote(strings.TrimSpace(ref))
		// A digest pin carries its own answer; the tag in front of it is still
		// the tag the file names, so keep it and drop the digest.
		if at := strings.Index(bare, "@"); at >= 0 {
			bare = bare[:at]
		}
		repo, tag, ok := SplitRef(bare)
		if !ok || repo == "" || tag == "" {
			continue
		}
		if key := repo + ":" + tag; !seen[key] {
			seen[key] = true
			out = append(out, Ref{Repository: repo, Tag: tag})
		}
	}
	return out
}

// SplitImageLine splits a compose "image:" line into the part up to and
// including the key with its following whitespace, and the value after it.
func SplitImageLine(line string) (key, value string, ok bool) {
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

// SplitTrailingComment separates a value from a trailing YAML comment, keeping
// the comment so an operator's note survives a rewrite.
//
// A '#' only starts a comment when preceded by whitespace, which is what keeps
// a digest-pinned reference or a URL fragment from being cut in half.
func SplitTrailingComment(value string) (ref, trailer string) {
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

// Unquote strips a matching pair of surrounding quotes, returning the quote
// character used so a rewrite can put back what was there.
func Unquote(s string) (quote, bare string) {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return string(s[0]), s[1 : len(s)-1]
		}
	}
	return "", s
}

// SplitRef splits repository:tag.
//
// The colon is found after the last slash, because a registry may carry a port:
// splitting "registry.example.com:5000/app" on the first colon yields a
// repository of "registry.example.com" and a tag of "5000/app", which is wrong
// in a way nobody notices until it is their registry.
func SplitRef(ref string) (repo, tag string, ok bool) {
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon <= slash {
		return "", "", false // no tag
	}
	return ref[:colon], ref[colon+1:], true
}
