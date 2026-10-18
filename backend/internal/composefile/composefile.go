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

// ServiceFor returns the name of the service whose image is repo:tag, or "" when
// the file does not name it.
//
// The compose file is the right place to ask. The engine used to find the
// service from a RUNNING container matching repository:tag -- which fails for
// exactly the update that matters most: a file pinned to v1.6.0-ls356 whose
// container is still on :latest names no container at that tag, so the lookup
// returned "" and the deploy fell back to the whole project. On a media stack
// that meant recreating gluetun and everything sharing its network namespace in
// order to update one service.
//
// A service key is the last key shallower than the "image:" line, which holds
// for two-space and four-space files alike without assuming either.
// ServiceFor returns the FIRST compose service whose image matches, or "" for
// none. Prefer ServicesFor: one image can legitimately back several services,
// and acting on only the first leaves the rest behind.
func ServiceFor(compose, repo, tag string) string {
	if svcs := ServicesFor(compose, repo, tag); len(svcs) > 0 {
		return svcs[0]
	}
	return ""
}

// ServicesFor returns EVERY compose service whose image is repo:tag, in file
// order.
//
// Plural because one image backing several services is ordinary -- a worker and
// a web process from one build, or (the case that found this) a model router and
// a dedicated embedding server from one llama.cpp image. A caller that narrows a
// deploy to the first match brings up one of them and leaves the others running
// the old image, while the compose file on disk claims otherwise: the running
// state and the declared state disagree, and the next unrelated `up -d` in that
// project silently recreates the stragglers.
func ServicesFor(compose, repo, tag string) []string {
	want := repo + ":" + tag
	var found []string
	seen := map[string]bool{}
	var inServices bool
	servicesIndent, serviceIndent := 0, -1
	service := ""

	for _, line := range strings.Split(compose, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(trimmed)

		// The services block, found rather than assumed: an anchor such as
		// "x-shared: &shared" carrying an image: line lives outside it, and
		// narrowing a deploy to the wrong name is worse than not narrowing at
		// all -- it reports an update that never touched the service it named.
		if !inServices {
			if strings.TrimRight(trimmed, " \t") == "services:" {
				inServices, servicesIndent = true, indent
			}
			continue
		}
		if indent <= servicesIndent {
			break // out of the block: "volumes:", "networks:"
		}

		if _, value, ok := SplitImageLine(line); ok {
			if service == "" || indent <= serviceIndent {
				continue
			}
			ref, _ := SplitTrailingComment(value)
			_, bare := Unquote(strings.TrimSpace(ref))
			if at := strings.Index(bare, "@"); at >= 0 {
				bare = bare[:at]
			}
			if strings.TrimSpace(bare) == want && !seen[service] {
				seen[service] = true
				found = append(found, service)
			}
			continue
		}

		// A service key is one at the block's first level of indentation.
		key, rest, ok := strings.Cut(trimmed, ":")
		if !ok || strings.TrimSpace(rest) != "" || key == "" {
			continue
		}
		if serviceIndent < 0 {
			serviceIndent = indent
		}
		if indent == serviceIndent {
			service = key
		}
	}
	return found
}

// DependsOn returns, for each service in the file, the services its depends_on
// names, in file order.
//
// All three spellings compose accepts are read: a block list ("- db"), an inline
// list ("[db, redis]"), and the long form, where each dependency is a key carrying
// its own condition. Only the names are kept; the condition is compose's business.
//
// A rollout needs this to decide ORDER. Nextcloud runs its database migration in
// its entrypoint, and a rollout that updated nextcloud and then, a minute later,
// the mariadb it depends_on, recreated the database underneath that migration:
// "MySQL server has gone away", "Update failed", and the instance left in
// maintenance mode. The file said which one the other needs. Reading it is how
// the database goes first.
func DependsOn(compose string) map[string][]string {
	out := map[string][]string{}
	var inServices bool
	servicesIndent, serviceIndent := 0, -1
	service := ""
	inDeps := false
	depsIndent, depsChild := 0, -1

	add := func(dep string) {
		dep, _ = SplitTrailingComment(dep)
		_, dep = Unquote(strings.TrimSpace(dep))
		if dep = strings.TrimSpace(dep); dep != "" && service != "" {
			out[service] = append(out[service], dep)
		}
	}

	for _, line := range strings.Split(compose, "\n") {
		line = strings.TrimRight(line, " \t\r")
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(trimmed)

		// The services block, found the same way ServicesFor finds it.
		if !inServices {
			if trimmed == "services:" {
				inServices, servicesIndent = true, indent
			}
			continue
		}
		if indent <= servicesIndent {
			break
		}

		if inDeps {
			if indent > depsIndent {
				if depsChild < 0 {
					depsChild = indent
				}
				// Only the first level under depends_on names services; deeper
				// lines are a long-form entry's condition and restart settings.
				if indent == depsChild {
					if item, ok := strings.CutPrefix(trimmed, "- "); ok {
						add(item)
					} else if key, _, ok := strings.Cut(trimmed, ":"); ok {
						add(key)
					}
				}
				continue
			}
			inDeps = false
		}

		key, rest, ok := strings.Cut(trimmed, ":")
		if !ok {
			continue
		}
		if serviceIndent < 0 {
			serviceIndent = indent
		}
		if indent == serviceIndent {
			if strings.TrimSpace(rest) == "" {
				service = key
			}
			continue
		}
		if service == "" || key != "depends_on" {
			continue
		}
		value, _ := SplitTrailingComment(strings.TrimSpace(rest))
		value = strings.TrimSpace(value)
		if inline, ok := strings.CutPrefix(value, "["); ok {
			for _, dep := range strings.Split(strings.TrimSuffix(inline, "]"), ",") {
				add(dep)
			}
			continue
		}
		inDeps, depsIndent, depsChild = true, indent, -1
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
