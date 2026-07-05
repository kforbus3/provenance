package federation

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// handleProxy will relay a management HTTP request into a site's own /api/v1 over
// the control channel, carrying a hub-signed acting-user assertion (F4). The hub
// enforces central RBAC before calling this. Scaffold: the stream framing and
// site-ingress dispatch are staged for Phase F3/F4.
func (s *Service) handleProxy(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad site id")
		return
	}
	if _, ok := s.registry.Get(siteID); !ok {
		writeErr(w, http.StatusServiceUnavailable, "site is not currently linked")
		return
	}
	writeErr(w, http.StatusNotImplemented, "management proxy is implemented in phase F4")
}

// handleProxyTerminal will proxy a browser terminal WebSocket to a site host over
// the control channel (F3), preserving the binary/text frame protocol. Scaffold.
func (s *Service) handleProxyTerminal(w http.ResponseWriter, r *http.Request) {
	siteID, err := uuid.Parse(chi.URLParam(r, "siteId"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad site id")
		return
	}
	if _, ok := s.registry.Get(siteID); !ok {
		writeErr(w, http.StatusServiceUnavailable, "site is not currently linked")
		return
	}
	writeErr(w, http.StatusNotImplemented, "terminal proxy is implemented in phase F3")
}
