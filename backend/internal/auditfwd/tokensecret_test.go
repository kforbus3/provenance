package auditfwd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kforbus3/provenance/backend/internal/secretbox"
)

var passphrase = []byte("a-qa-passphrase-at-least-16-bytes")

// The collector token is a credential and must not be readable from the API.
//
// It was: GET /audit/forwarding returned
//
//	{"enabled":true,"type":"http","address":"...","token":"qa-collector-token"}
//
// and PUT echoed the same thing straight back. Every other configuration endpoint
// in this product withholds its secret and returns a boolean -- the OIDC client
// secret (secretSet), the SMTP password (passwordSet), the PagerDuty routing key,
// the SAML SP key (spKeySet), the LDAP bind password. This one did neither, so the
// credential was in the response body, in browser devtools, in any proxy log, and
// in plaintext in the settings table and therefore in every database backup.
func TestTheTokenIsNeverReturned(t *testing.T) {
	enc, err := secretbox.Seal(passphrase, []byte("qa-collector-token"))
	if err != nil {
		t.Fatal(err)
	}
	c := Config{Enabled: true, Type: "http", Address: "http://collector/audit", TokenEnc: enc}

	// The send path can still get at it.
	if got := c.tokenValue(passphrase); got != "qa-collector-token" {
		t.Fatalf("the sealed token did not open: %q", got)
	}

	body, err := json.Marshal(c.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"qa-collector-token", enc, "token\":", "tokenEnc"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("the redacted config carries %q:\n%s", leak, body)
		}
	}
	// But it still says whether one is set, or nobody can tell a configured
	// collector from an unauthenticated one.
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out["tokenSet"] != true {
		t.Errorf("tokenSet is %v, want true", out["tokenSet"])
	}
	if out["address"] != "http://collector/audit" {
		t.Errorf("the address was redacted too: %v", out["address"])
	}

	// And an unconfigured token reads as absent rather than missing.
	var empty Config
	b2, _ := json.Marshal(empty.Redacted())
	var out2 map[string]any
	_ = json.Unmarshal(b2, &out2)
	if out2["tokenSet"] != false {
		t.Errorf("tokenSet is %v for an empty config, want false", out2["tokenSet"])
	}
}

// A deployment configured before the token was sealed has it stored as plaintext.
// Refusing to read that would stop authenticating to its collector, turning a
// storage fix into an outage.
func TestALegacyPlaintextTokenStillWorks(t *testing.T) {
	c := Config{Enabled: true, Type: "http", Token: "old-plaintext-token"}
	if got := c.tokenValue(passphrase); got != "old-plaintext-token" {
		t.Errorf("a legacy plaintext token was dropped: %q", got)
	}
	if !c.HasToken() {
		t.Error("HasToken says no for a legacy plaintext token")
	}
	// And it is not published either.
	b, _ := json.Marshal(c.Redacted())
	if strings.Contains(string(b), "old-plaintext-token") {
		t.Errorf("a legacy token is published: %s", b)
	}
}

// A token that cannot be opened must read as absent rather than as garbage sent
// to the collector as a bearer credential.
func TestAnUnopenableTokenIsNotSentAsGarbage(t *testing.T) {
	c := Config{TokenEnc: "not-a-sealed-value"}
	if got := c.tokenValue(passphrase); got != "" {
		t.Errorf("tokenValue returned %q for an unopenable token", got)
	}
}
