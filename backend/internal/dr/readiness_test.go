package dr

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The standby console reported "promotion enabled" from the presence of a token alone.
// QA pressed the button during a simulated site loss and got
// `permission denied for function pg_promote (SQLSTATE 42501)`: pg_promote is
// superuser-only unless EXECUTE is granted, and a multi-tenant deployment is REQUIRED to
// connect as a non-superuser. The console was promising something it had never checked,
// at the one moment nobody can afford to find out.
//
// Worse, the fix cannot be applied at that point: a standby is read-only, so the grant
// has to exist on the primary beforehand. Readiness has to be honest in advance.
func TestPromotionReadinessAsksTheDatabase(t *testing.T) {
	src, err := os.ReadFile("standby.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	// The EXPRESSION assigned to promotionEnabled, not the neighbourhood around it: the
	// first version of this test read the following 120 characters, which swept in the
	// canPromote reference from the very next statement -- so restoring the defect left
	// it passing. Captured precisely now.
	m := regexp.MustCompile(`"promotionEnabled":\s*([^,\n]+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("promotionEnabled not reported at all")
	}
	if !strings.Contains(m[1], "canPromote") {
		t.Errorf("promotionEnabled is computed as %q -- without asking whether the database "+
			"role can call pg_promote()", strings.TrimSpace(m[1]))
	}
	if !strings.Contains(body, "CanPromoteDB") {
		t.Error("the standby console never asks CanPromoteDB")
	}
	// And when it cannot, it must say what to do -- during a failover, "permission
	// denied" with no remedy is a dead end.
	if !strings.Contains(body, "GRANT EXECUTE ON FUNCTION pg_promote") {
		t.Error("the blocked-promotion message does not name the grant that fixes it")
	}
}
