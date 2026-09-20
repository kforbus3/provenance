// Package transienterr recognises failures that are worth attempting again.
//
// It exists because of one production rollout. Three images were being updated
// across two hosts; the first host's pull came back with
//
//	toomanyrequests: retry-after: 548.005µs, allowed: 44000/minute
//
// The registry was asking to be called back in half a millisecond. Nothing
// called it back: the pull was one attempt, its failure was recorded as the
// host's failure, the failure budget was one host, and the rollout halted with
// the second host left pending forever. A rate limit that resolves itself faster
// than a person can read it ended a fleet-wide update.
//
// The distinction that matters is not "did it fail" but "would the same command
// succeed if run again in a moment". An unauthorized registry, an image that
// does not exist, a compose file compose cannot read: those are answers, and
// repeating them wastes time and hides the real message. A rate limit, a TLS
// handshake that timed out, a connection a CDN reset mid-layer: those are
// weather.
//
// Both the deploy script and the rollout engine need this judgement, from
// opposite sides -- the script retries within one deploy, the engine retries
// across ticks -- so the vocabulary lives in one place rather than being
// written twice and drifting.
package transienterr

import "strings"

// Tokens are lowercase substrings that mark a retryable failure.
//
// Deliberately narrow. A token here that also appears in a permanent failure
// turns a clear error message into the same message three times, several
// minutes later, which is worse than failing at once. Everything not listed is
// treated as final.
//
// Must contain no shell pattern characters: these are compiled into a `case`
// statement for the deploy script, and a `*` or `[` inside one would match
// something nobody intended. Enforced by TestTokensAreShellSafe.
var Tokens = []string{
	// Registry rate limits. Docker Hub and GHCR both answer this way, and both
	// mean "ask again shortly" rather than "no".
	"toomanyrequests",
	"too many requests",
	"429 ",
	// Registry and proxy unavailability. A 5xx from a registry is the registry's
	// problem, not this fleet's.
	"500 internal server error",
	"502 bad gateway",
	"503 service unavailable",
	"504 gateway",
	"service unavailable",
	"temporarily unavailable",
	// Transport. Layer pulls are long-lived HTTPS streams over other people's
	// CDNs, and they break mid-download as a matter of routine.
	"tls handshake timeout",
	"i/o timeout",
	"connection reset by peer",
	"unexpected eof",
	"connection refused",
	"no route to host",
	"network is unreachable",
	"context deadline exceeded",
	"client timeout exceeded",
	"request canceled",
	// containerd/dockerd wording for a layer fetch that died in transit.
	"error pulling image configuration",
	"failed to copy",
	"unexpected status from head request",
}

// Is reports whether msg looks like a failure worth another attempt.
//
// Case-insensitive: the same condition reaches here as "TLS handshake timeout"
// from Go's http client and "tls handshake timeout" from the docker CLI.
func Is(msg string) bool {
	low := strings.ToLower(msg)
	for _, t := range Tokens {
		if strings.Contains(low, t) {
			return true
		}
	}
	return false
}

// ShellCase renders Tokens as the pattern list of a POSIX `case` arm, so the
// deploy script asks exactly the question Is asks.
//
// The caller lowercases the subject first (tr A-Z a-z); these patterns are
// lowercase.
//
// Each token is single-quoted. Most of them contain spaces, and an unquoted
// space inside a case pattern ends the pattern -- `*too many requests*)` is not
// a wide pattern, it is a syntax error, and it took the whole deploy script down
// with exit 2 before a single image was pulled. The surrounding * stay outside
// the quotes, where they are still globs.
func ShellCase() string {
	parts := make([]string, 0, len(Tokens))
	for _, t := range Tokens {
		parts = append(parts, "*'"+t+"'*")
	}
	return strings.Join(parts, "|")
}
