package cpe

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct{ name, vendor, product string }{
		{"Google Chrome", "google", "chrome"},
		{"Mozilla Firefox (x64 en-US)", "mozilla", "firefox"},
		{"7-Zip 23.01 (x64)", "7-zip", "7-zip"},
		{"VLC media player", "videolan", "vlc_media_player"},
		{"Python 3.11.5 (64-bit)", "python", "python"},
	}
	for _, c := range cases {
		v, p, ok := Match(c.name)
		if !ok || v != c.vendor || p != c.product {
			t.Errorf("Match(%q) = %q/%q/%v, want %q/%q", c.name, v, p, ok, c.vendor, c.product)
		}
	}
	if _, _, ok := Match("Some Random App"); ok {
		t.Error("unexpected match for unknown app")
	}
	// Bare "Python" (launcher/library) must NOT match the "python 3" rule.
	if _, _, ok := Match("Python Launcher"); ok {
		t.Error("Python Launcher should not match")
	}
}

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"120.0.6099.109 (x64)": "120.0.6099.109",
		"v1.2.3":               "1.2.3",
		"23.01":                "23.01",
		"":                     "",
		"unknown":              "",
	}
	for in, want := range cases {
		if got := NormalizeVersion(in); got != want {
			t.Errorf("NormalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCPE(t *testing.T) {
	got := CPE("google", "chrome", "120.0.6099.109 (x64)")
	want := "cpe:2.3:a:google:chrome:120.0.6099.109:*:*:*:*:*:*:*"
	if got != want {
		t.Errorf("CPE = %q, want %q", got, want)
	}
	if CPE("google", "chrome", "") != "" {
		t.Error("versionless CPE should be empty")
	}
}
