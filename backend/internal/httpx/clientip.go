package httpx

import (
	"net"
	"net/http"
)

// ClientIP returns the address a request came from.
//
// It reads RemoteAddr and nothing else. The realIP middleware runs on every
// route and has already replaced RemoteAddr with the real client address when —
// and only when — the direct peer is a trusted proxy, so by the time any
// handler runs, RemoteAddr is the answer.
//
// This existed six times under two names with three different behaviours. Two
// copies read RemoteAddr, as here. Four (k8sbroker, dbbroker, accesspolicyapi
// and accesspolicy.RequestIP, used by sftp and command) read the LEFT-MOST
// X-Forwarded-For entry instead, unconditionally and with no trust check.
//
// That last group is the whole spoofing problem the middleware exists to solve,
// re-introduced downstream of it: the left-most entry is the one the CALLER
// wrote. Any authenticated user could send `X-Forwarded-For: 10.9.9.9` and have
// that recorded as the origin of their Kubernetes exec, their database query,
// their SFTP transfer and their ad-hoc command — in the audit records that
// exist precisely to say where an action came from.
//
// An unparseable address yields "" rather than a made-up value: an audit record
// admitting it does not know beats one asserting something false.
func ClientIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if net.ParseIP(host) == nil {
		return ""
	}
	return host
}
