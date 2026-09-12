package monitor

import (
	"os"
	"strings"
	"testing"
)

// readSource returns a file in this package, for the few assertions that are
// about how the code is wired rather than what it computes.
func readSource(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

// between returns the text from the first occurrence of start up to the next
// occurrence of end after it.
func between(src, start, end string) string {
	i := strings.Index(src, start)
	if i < 0 {
		return ""
	}
	rest := src[i:]
	if j := strings.Index(rest, end); j > 0 {
		return rest[:j]
	}
	return rest
}
