package scim

import (
	"encoding/json"
	"testing"
)

func TestParseUserNameEq(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`userName eq "alice"`, "alice", true},
		{`username eq "Bob"`, "Bob", true}, // attribute name is case-insensitive
		{`  userName eq "carol@example.com"  `, "carol@example.com", true},
		{`displayName eq "x"`, "", false},  // unsupported attribute
		{`userName co "alice"`, "", false}, // unsupported operator
		{`userName eq ""`, "", false},      // empty value
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := parseUserNameEq(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseUserNameEq(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestDecodeBool(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		ok   bool
	}{
		{`true`, true, true},
		{`false`, false, true},
		{`"true"`, true, true}, // some IdPs send active as a string
		{`"false"`, false, true},
		{`123`, false, false},
	}
	for _, c := range cases {
		got, ok := decodeBool(json.RawMessage(c.in))
		if ok != c.ok || got != c.want {
			t.Errorf("decodeBool(%s) = (%v,%v), want (%v,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestScimUserMapping(t *testing.T) {
	body := `{
		"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"dave",
		"name":{"givenName":"Dave","familyName":"Grohl"},
		"emails":[{"value":"secondary@x.com"},{"value":"dave@x.com","primary":true}],
		"active":false
	}`
	var u scimUser
	if err := json.Unmarshal([]byte(body), &u); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := u.primaryEmail(); got != "dave@x.com" {
		t.Errorf("primaryEmail = %q, want dave@x.com", got)
	}
	if got := u.displayName(); got != "Dave Grohl" {
		t.Errorf("displayName = %q, want 'Dave Grohl'", got)
	}
	if u.Active {
		t.Error("active should be false")
	}
}

func TestScimUserDisplayNamePrefersExplicit(t *testing.T) {
	u := scimUser{DisplayName: "Explicit", Name: &scimName{Formatted: "Formatted"}}
	if got := u.displayName(); got != "Explicit" {
		t.Errorf("displayName = %q, want Explicit", got)
	}
}

func TestConfigDefaults(t *testing.T) {
	var c scimConfig
	if c.authSource() != "saml" {
		t.Errorf("default authSource = %q, want saml", c.authSource())
	}
	if c.defaultRole() != "Read-Only" {
		t.Errorf("default role = %q, want Read-Only", c.defaultRole())
	}
	if (scimConfig{AuthSource: "oidc"}).authSource() != "oidc" {
		t.Error("explicit oidc authSource should pass through")
	}
	if (scimConfig{AuthSource: "bogus"}).authSource() != "saml" {
		t.Error("invalid authSource should fall back to saml")
	}
}
