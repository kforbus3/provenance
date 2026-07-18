package assistant

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

//go:generate go run gendocs.go -docs ../../../docs -out docs_generated.go

// embeddedDoc is one curated documentation page, embedded at build time by
// gendocs.go from the repository docs/ directory (the single source of truth).
// The list is defined in the generated docs_generated.go.
type embeddedDoc struct {
	Slug     string
	Title    string
	Markdown string
}

// DocSource is a citation returned to the UI so an answer can link back into the
// in-app help at the exact section (/help/<slug>#<anchor>).
type DocSource struct {
	DocTitle string `json:"docTitle"`
	Heading  string `json:"heading"`
	Slug     string `json:"slug"`
	Anchor   string `json:"anchor"`
}

// docSection is one heading-delimited chunk of a doc — the unit of retrieval.
type docSection struct {
	DocSlug  string
	DocTitle string
	Heading  string
	Anchor   string
	Text     string
	tokens   map[string]int // term -> frequency (heading + body), for BM25
	length   int            // token count
}

var (
	docIndexOnce sync.Once
	docSections  []docSection
	docAvgLen    float64
	docDF        map[string]int // term -> number of sections containing it
)

var (
	reHeading = regexp.MustCompile(`^(#{1,6})\s+(.*)$`)
	reNonSlug = regexp.MustCompile(`[^\w\s-]`)
	reSpaces  = regexp.MustCompile(`\s+`)
	reDashes  = regexp.MustCompile(`-+`)
	reWord    = regexp.MustCompile(`[^a-z0-9]+`)
	headClean = strings.NewReplacer("#", "", "*", "", "`", "")
)

// slugifyHeading mirrors the frontend heading-id function (build-help.mjs /
// HelpPage) exactly, so citation anchors line up with the in-app help.
func slugifyHeading(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, "`", "")
	s = reNonSlug.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)
	s = reSpaces.ReplaceAllString(s, "-")
	s = reDashes.ReplaceAllString(s, "-")
	return s
}

// docStopwords are common terms excluded from indexing/queries so scoring keys
// on meaningful words.
var docStopwords = map[string]bool{
	"the": true, "and": true, "for": true, "with": true, "that": true, "this": true,
	"are": true, "you": true, "can": true, "how": true, "does": true, "what": true,
	"from": true, "into": true, "your": true, "use": true, "used": true, "when": true,
	"which": true, "will": true, "not": true, "all": true, "any": true, "its": true,
	"has": true, "have": true, "each": true, "per": true, "via": true, "set": true,
}

func tokenizeDoc(s string) []string {
	parts := reWord.Split(strings.ToLower(s), -1)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) < 2 || docStopwords[p] {
			continue
		}
		out = append(out, p)
	}
	return out
}

func splitDocSections(d embeddedDoc) []docSection {
	var out []docSection
	var cur *docSection
	flush := func() {
		if cur != nil && strings.TrimSpace(cur.Text) != "" {
			toks := tokenizeDoc(cur.Heading + " " + cur.Text)
			m := make(map[string]int, len(toks))
			for _, t := range toks {
				m[t]++
			}
			cur.tokens, cur.length = m, len(toks)
			out = append(out, *cur)
		}
	}
	for _, line := range strings.Split(d.Markdown, "\n") {
		if h := reHeading.FindStringSubmatch(line); h != nil {
			flush()
			heading := strings.TrimSpace(headClean.Replace(h[2]))
			cur = &docSection{DocSlug: d.Slug, DocTitle: d.Title, Heading: heading, Anchor: slugifyHeading(heading)}
			continue
		}
		if cur == nil {
			// Preamble before the first heading: attach it to a doc-titled section.
			cur = &docSection{DocSlug: d.Slug, DocTitle: d.Title, Heading: d.Title}
		}
		cur.Text += line + "\n"
	}
	flush()
	return out
}

func buildDocIndex() {
	for _, d := range embeddedDocs {
		docSections = append(docSections, splitDocSections(d)...)
	}
	docDF = make(map[string]int)
	total := 0
	for i := range docSections {
		for t := range docSections[i].tokens {
			docDF[t]++
		}
		total += docSections[i].length
	}
	if len(docSections) > 0 {
		docAvgLen = float64(total) / float64(len(docSections))
	}
}

// searchDocs returns the top-k documentation sections most relevant to the query,
// scored with BM25 over the section index. Read-only, no external calls.
func searchDocs(query string, k int) []docSection {
	docIndexOnce.Do(buildDocIndex)
	terms := tokenizeDoc(query)
	if len(terms) == 0 || len(docSections) == 0 {
		return nil
	}
	const k1, b = 1.5, 0.75
	n := float64(len(docSections))
	type scored struct {
		i     int
		score float64
	}
	var ranked []scored
	for i := range docSections {
		sec := &docSections[i]
		var score float64
		for _, term := range terms {
			tf := float64(sec.tokens[term])
			if tf == 0 {
				continue
			}
			df := float64(docDF[term])
			idf := math.Log(1 + (n-df+0.5)/(df+0.5))
			denom := tf + k1*(1-b+b*float64(sec.length)/docAvgLen)
			score += idf * (tf * (k1 + 1)) / denom
		}
		if score > 0 {
			ranked = append(ranked, scored{i, score})
		}
	}
	sort.SliceStable(ranked, func(a, b int) bool { return ranked[a].score > ranked[b].score })
	if len(ranked) > k {
		ranked = ranked[:k]
	}
	out := make([]docSection, 0, len(ranked))
	for _, r := range ranked {
		out = append(out, docSections[r.i])
	}
	return out
}

// clipText trims a section body to n runes for inclusion in a tool result.
func clipText(s string, n int) string {
	s = strings.TrimSpace(reSpaces.ReplaceAllString(s, " "))
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
