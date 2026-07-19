package msrc

import "testing"

const sampleCVRF = `{
  "DocumentTracking": { "Identification": { "ID": { "Value": "2026-Jul" } } },
  "Vulnerability": [
    {
      "Title": { "Value": "Remote Code Execution in Widget" },
      "CVE": "CVE-2026-1234",
      "Threats": [
        { "Type": 0, "Description": { "Value": "Remote Code Execution" } },
        { "Type": 3, "Description": { "Value": "Critical" } }
      ],
      "CVSSScoreSets": [
        { "BaseScore": 7.5, "Vector": "CVSS:3.1/low" },
        { "BaseScore": 9.8, "Vector": "CVSS:3.1/AV:N/AC:L" }
      ],
      "Remediations": [
        { "Type": 2, "Description": { "Value": "5099536" }, "SubType": "Security Update" },
        { "Type": 2, "Description": { "Value": "KB5100998" } },
        { "Type": 0, "Description": { "Value": "not a kb" } }
      ]
    },
    {
      "Title": { "Value": "No CVE" },
      "CVE": "",
      "Remediations": [ { "Type": 2, "Description": { "Value": "5000001" } } ]
    }
  ]
}`

func TestParseCVRF(t *testing.T) {
	rows, err := ParseCVRF([]byte(sampleCVRF))
	if err != nil {
		t.Fatalf("ParseCVRF: %v", err)
	}
	// Two KB remediations for one CVE (the empty-CVE vuln is skipped, the non-KB
	// remediation is ignored).
	if len(rows) != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", len(rows), rows)
	}
	kbs := map[string]bool{}
	for _, r := range rows {
		kbs[r.KB] = true
		if r.CVE != "CVE-2026-1234" {
			t.Errorf("unexpected CVE %q", r.CVE)
		}
		if r.Severity != "Critical" {
			t.Errorf("want severity Critical, got %q", r.Severity)
		}
		if r.CVSS != 9.8 { // highest of the two score sets
			t.Errorf("want CVSS 9.8, got %v", r.CVSS)
		}
		if r.Release != "2026-Jul" {
			t.Errorf("want release 2026-Jul, got %q", r.Release)
		}
	}
	if !kbs["5099536"] || !kbs["5100998"] {
		t.Errorf("expected KBs 5099536 and 5100998, got %v", kbs)
	}
}

func TestKBNumber(t *testing.T) {
	cases := map[string]string{
		"5099536": "5099536", "KB5099536": "5099536", "kb5100998": "5100998",
		"not a kb": "", "": "", "123": "", "https://x": "",
	}
	for in, want := range cases {
		if got := kbNumber(in); got != want {
			t.Errorf("kbNumber(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitDocsArray(t *testing.T) {
	docs, err := splitDocs([]byte(`[{"a":1},{"b":2}]`))
	if err != nil {
		t.Fatalf("splitDocs: %v", err)
	}
	if len(docs) != 2 {
		t.Fatalf("want 2 docs, got %d", len(docs))
	}
}
