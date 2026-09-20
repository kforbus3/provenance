package dr

import (
	"os"
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
	i := strings.Index(body, `"promotionEnabled"`)
	if i < 0 {
		t.Fatal("promotionEnabled not reported at all")
	}
	// The line must depend on more than the token.
	line := body[i:min(i+120, len(body))]
	if !strings.Contains(line, "canPromote") {
		t.Errorf("promotionEnabled is reported without asking whether the database role "+
			"can call pg_promote(): %q", strings.TrimSpace(line))
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
