package auditapi

import (
	"net/http/httptest"
	"strconv"
	"testing"
)

// Verification names sequence numbers — "broken at sequence 2", "not tamper-evident
// from sequence 3389" — and there was no way to retrieve the row it named. Being told
// which event to investigate and given no means to look at it is a strange place for
// an audit tool to leave somebody.
func TestSequenceParamsPinAnEvent(t *testing.T) {
	parse := func(q string) (from, to *int64, bad bool) {
		r := httptest.NewRequest("GET", "/api/v1/audit?"+q, nil)
		if v := r.URL.Query().Get("seq"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 {
				return nil, nil, true
			}
			return &n, &n, false
		}
		for _, b := range []struct {
			param string
			dst   **int64
		}{{"seqFrom", &from}, {"seqTo", &to}} {
			v := r.URL.Query().Get(b.param)
			if v == "" {
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 {
				return nil, nil, true
			}
			*b.dst = &n
		}
		return from, to, false
	}

	// seq pins exactly one event, both ends.
	from, to, bad := parse("seq=3389")
	if bad || from == nil || to == nil || *from != 3389 || *to != 3389 {
		t.Fatalf("seq=3389 gave from=%v to=%v bad=%v", from, to, bad)
	}

	// A span for inspecting a whole acknowledged range.
	from, to, bad = parse("seqFrom=2&seqTo=5380")
	if bad || from == nil || to == nil || *from != 2 || *to != 5380 {
		t.Fatalf("span gave from=%v to=%v bad=%v", from, to, bad)
	}

	// Nonsense is refused rather than silently ignored, which would show the whole
	// log and look like the filter had been applied.
	for _, q := range []string{"seq=abc", "seq=0", "seq=-1", "seqFrom=x"} {
		if _, _, bad := parse(q); !bad {
			t.Errorf("%q was accepted", q)
		}
	}

	// No params means no bound.
	if from, to, bad := parse("action=auth.login"); bad || from != nil || to != nil {
		t.Errorf("unfiltered request produced bounds: %v %v %v", from, to, bad)
	}
}
