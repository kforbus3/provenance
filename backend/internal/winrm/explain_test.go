package winrm

import (
	"errors"
	"strings"
	"testing"
)

// The error a stock Windows host produces says nothing about why it refused.
//
// Windows defaults WinRM's AllowUnencrypted to false and this client cannot do WinRM
// message encryption over HTTP, so a host set up with a plain `Enable-PSRemoting` —
// the documented way to set one up — refuses every fact collection with
//
//	http response error: 401 - invalid content type
//
// which names neither the encryption requirement, nor the port, nor the fix. Measured
// on a real Windows Server 2025 host: flipping AllowUnencrypted to true makes the
// identical call succeed, so the cause is not in doubt.
func TestTheUnencryptedRefusalExplainsItself(t *testing.T) {
	raw := errors.New("http response error: 401 - invalid content type")
	got := explainFailure(raw, []int{5986, 5985}).Error()

	for _, want := range []string{"AllowUnencrypted", "5986", "clear text"} {
		if !strings.Contains(got, want) {
			t.Errorf("the explanation does not mention %q, so a reader still has to guess:\n%s",
				want, got)
		}
	}
	// The original stays wrapped: the explanation is the likely cause, not a
	// certainty, and a 401 really can just be a wrong password.
	if !errors.Is(explainFailure(raw, []int{5985}), raw) {
		t.Error("the underlying error was discarded; it is the only evidence of what the " +
			"host actually said")
	}
	if !strings.Contains(got, "credentials") {
		t.Error("the explanation asserts the cause without admitting a 401 can also be a " +
			"refused credential")
	}
}

// Every other failure is passed through untouched — a timeout or a refused connection
// has nothing to do with encryption, and dressing it up as if it did would send an
// operator to the wrong place.
func TestOtherFailuresArePassedThrough(t *testing.T) {
	for _, raw := range []error{
		errors.New("dial tcp 10.0.0.9:5986: i/o timeout"),
		errors.New("winrm command exited 1"),
	} {
		got := explainFailure(raw, []int{5986, 5985})
		if got.Error() != raw.Error() {
			t.Errorf("%v was rewritten as %v", raw, got)
		}
	}
	if explainFailure(nil, []int{5985}) != nil {
		t.Error("a nil error became non-nil")
	}
}
