package assistant

import (
	"strings"
	"testing"
)

func TestSlugifyHeadingMatchesFrontend(t *testing.T) {
	// These must match frontend build-help.mjs / HelpPage slugify so /help links line up.
	cases := map[string]string{
		"Single sign-on (SAML)":   "single-sign-on-saml",
		"1. Prerequisites":        "1-prerequisites",
		"SCIM 2.0 provisioning":   "scim-20-provisioning",
		"`fleet` CLI":             "fleet-cli",
		"Audit forwarding (SIEM)": "audit-forwarding-siem",
	}
	for in, want := range cases {
		if got := slugifyHeading(in); got != want {
			t.Errorf("slugifyHeading(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitDocSections(t *testing.T) {
	doc := embeddedDoc{Slug: "guide", Title: "Guide", Markdown: "# Guide\nintro text\n## Setup\ninstall the thing\n## Config\ntweak the config\n"}
	secs := splitDocSections(doc)
	if len(secs) != 3 {
		t.Fatalf("want 3 sections, got %d", len(secs))
	}
	if secs[1].Heading != "Setup" || secs[1].Anchor != "setup" {
		t.Errorf("section[1] = %+v", secs[1])
	}
	if !strings.Contains(secs[1].Text, "install the thing") {
		t.Errorf("section[1] text = %q", secs[1].Text)
	}
}

func TestSearchDocsRanksRelevantSection(t *testing.T) {
	// Point the index at a small fixed corpus for a deterministic assertion.
	docIndexOnce.Do(func() {}) // consume the Once so buildDocIndex won't overwrite
	docSections = nil
	docSections = append(docSections, splitDocSections(embeddedDoc{
		Slug: "admin", Title: "Administration",
		Markdown: "# Administration\n## Single sign-on (SAML)\nConfigure the IdP entity ID, SSO URL, and signing certificate to enable SAML sign-on.\n## Backups\nSchedule encrypted database backups and store them off host.\n",
	})...)
	docSections = append(docSections, splitDocSections(embeddedDoc{
		Slug: "enroll", Title: "Host Enrollment",
		Markdown: "# Host Enrollment\n## Enrolling a host\nRun the enrollment script over SSH to register a managed host.\n",
	})...)
	docDF = map[string]int{}
	total := 0
	for i := range docSections {
		for tok := range docSections[i].tokens {
			docDF[tok]++
		}
		total += docSections[i].length
	}
	docAvgLen = float64(total) / float64(len(docSections))

	res := searchDocs("how do I configure SAML single sign-on", 3)
	if len(res) == 0 {
		t.Fatal("expected results for a SAML query")
	}
	if res[0].Heading != "Single sign-on (SAML)" {
		t.Errorf("top result = %q, want the SAML section", res[0].Heading)
	}
	if searchDocs("", 3) != nil {
		t.Error("empty query should return nil")
	}
}
