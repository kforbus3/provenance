package monitor

import "testing"

func TestParseObsolete(t *testing.T) {
	// Representative `apt list --installed` output already filtered by the awk in
	// obsoleteScript to the package names on [installed,local] lines, plus blanks and
	// a duplicate to exercise de-duplication.
	out := "libdns-export1104\nlibapt-pkg6.0\n\nlibssl1.1\nlibdns-export1104\n  spl  \n"
	got := parseObsolete(out)
	want := []string{"libdns-export1104", "libapt-pkg6.0", "libssl1.1", "spl"}
	if len(got) != len(want) {
		t.Fatalf("got %d packages %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseObsoleteEmptyIsNonNil(t *testing.T) {
	// A successful check that finds nothing must return a non-nil empty slice so it is
	// stored as "checked, none obsolete" rather than preserving a stale list.
	got := parseObsolete("\n  \n")
	if got == nil {
		t.Fatal("parseObsolete returned nil for empty input; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %v", got)
	}
}

func TestParseObsoleteCap(t *testing.T) {
	var b []byte
	for i := 0; i < obsoletePackagesCap+50; i++ {
		b = append(b, []byte("pkg"+itoa(i)+"\n")...)
	}
	got := parseObsolete(string(b))
	if len(got) != obsoletePackagesCap {
		t.Fatalf("got %d, want cap %d", len(got), obsoletePackagesCap)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
