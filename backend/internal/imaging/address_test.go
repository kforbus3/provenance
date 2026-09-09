package imaging

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The address recorded for a machine must be the machine's, not a proxy's.
//
// The report arrives through the provisioning nginx and then the compose
// network, so the connection address is the Docker bridge gateway. Every
// machine ever imaged was recorded as 172.18.0.1, that value pre-filled the
// "add as host" form, and a host pointed at the bridge of the server watching it
// is a host nothing can reach — which surfaced as a freshly enrolled machine
// sitting there offline.
func post(form string, remote string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/imaging/report", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = remote
	return r
}

func TestMachineReportedAddressWins(t *testing.T) {
	got := reportedAddress(post("id=aa&address=192.168.50.160", "172.18.0.1:5000"))
	if got != "192.168.50.160" {
		t.Errorf("address = %q, want the machine's own 192.168.50.160. The "+
			"connection address is a proxy's and is never the machine's.", got)
	}
}

func TestFallsBackToTheConnectionWhenNothingIsReported(t *testing.T) {
	// An older imager sends no address field; recording the connection is still
	// better than recording nothing.
	got := reportedAddress(post("id=aa", "10.10.0.51:5000"))
	if got != "10.10.0.51" {
		t.Errorf("address = %q, want the connection address 10.10.0.51", got)
	}
}

func TestARubbishAddressIsNotBelieved(t *testing.T) {
	// This endpoint is unauthenticated by design, so the field is
	// attacker-controlled. It is only ever displayed and used to pre-fill a form
	// a person confirms — but it still must not store something that is not an
	// address at all.
	for _, bad := range []string{"not-an-ip", "192.168.50.999", "'; DROP TABLE", ""} {
		got := reportedAddress(post("id=aa&address="+bad, "10.10.0.51:5000"))
		if got != "10.10.0.51" {
			t.Errorf("address=%q was believed (got %q); it should have fallen back "+
				"to the connection address", bad, got)
		}
	}
}
