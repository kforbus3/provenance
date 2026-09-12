package appsupport

import (
	"regexp"
	"strings"
)

// Redaction, which is the whole security question a support bundle raises.
//
// This bundle exists to be SENT somewhere — attached to a ticket, emailed, put in
// a chat. Whatever it contains has left the building. The failure mode is not
// "the bundle is incomplete", it is "the bundle carried this instance's database
// password to a third party", and nobody reads a bundle closely enough to notice.
//
// So the rule here is deny-by-default: configuration is reported as an explicit
// list of non-secret fields, never by dumping the environment; and free text that
// has to be included — logs, mostly — is scrubbed for the shapes secrets take.
// Scrubbing text is a weaker guarantee than not collecting it, which is why it is
// the second line rather than the first.

// secretish matches the shapes credentials take in logs and config output.
//
// Deliberately greedy. A redacted line an engineer has to ask about costs a
// message; a leaked token costs a rotation, and only if somebody notices.
var secretish = []*regexp.Regexp{
	// key=value and key: value, where the key looks like a secret.
	regexp.MustCompile(`(?i)\b([a-z0-9_.-]*(?:passwo?rd|passphrase|secret|token|[_-]key|key[_-]|apikey|credential|auth)[a-z0-9_.-]*)\s*[:=]\s*("[^"]*"|'[^']*'|\S+)`),
	// Authorization headers, in either direction.
	regexp.MustCompile(`(?i)\b(authorization|x-updater-token|x-api-key|cookie|set-cookie)\s*[:=]\s*\S+`),
	// Connection strings with inline credentials: scheme://user:pass@host
	regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://)([^:/\s@]+):([^@/\s]+)@`),
	// PEM blocks, which are never diagnostic and always sensitive.
	regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`),
	// JWTs: three base64url segments. Distinctive enough not to catch prose.
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
}

const redacted = "[REDACTED]"

// Scrub removes credential-shaped text.
//
// Applied to everything free-form that goes into a bundle. It is not a
// substitute for not collecting a secret in the first place — a value that does
// not look like a secret survives it — which is why configuration goes through
// an allowlist instead of through here.
func Scrub(s string) string {
	out := s
	// Connection-string credentials: keep the scheme and user so a reader can
	// still tell WHICH database it is, which is usually the diagnostic point.
	out = secretish[2].ReplaceAllString(out, "${1}${2}:"+redacted+"@")
	out = secretish[3].ReplaceAllString(out, "-----BEGIN PRIVATE KEY-----"+redacted+"-----END PRIVATE KEY-----")
	out = secretish[4].ReplaceAllString(out, redacted)
	// Keep the KEY, drop the value: "which setting is set" is diagnostic,
	// "what it is set to" is not.
	out = secretish[0].ReplaceAllString(out, "${1}="+redacted)
	out = secretish[1].ReplaceAllString(out, "${1}: "+redacted)
	return out
}

// Set reports whether a value is configured, without revealing it.
//
// The diagnostic question about a secret is almost always "is it set" — an
// audit HMAC key that is empty explains a whole class of symptom, and its actual
// bytes explain nothing.
func Set(v string) string {
	if strings.TrimSpace(v) == "" {
		return "not set"
	}
	return "set"
}
