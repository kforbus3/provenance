// Package federation implements multi-site federation: a hub instance that is a
// single pane of glass over many independent site instances on separated
// networks. Sites dial OUT to the hub over a persistent multiplexed WSS channel
// (see internal/federation/link); the hub proxies management + live requests into
// each site's own unmodified /api/v1, and sites push a read-model to the hub.
//
// Everything here is mode-gated. A standalone instance (the default) constructs
// no Service and mounts no routes, so its behavior is unchanged.
package federation

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/fleet-terminal/backend/internal/app"
	"github.com/fleet-terminal/backend/internal/federation/link"
	"github.com/fleet-terminal/backend/internal/sshgw"
)

// Service holds federation state for whichever role this instance runs.
type Service struct {
	deps *app.Deps
	log  *slog.Logger

	// Hub role
	hubKeyID  string
	hubPriv   ed25519.PrivateKey
	hubPub    ed25519.PublicKey
	hubFinger string
	registry  *link.Registry

	// Site role
	siteHandler http.Handler   // the site's own router, for serving proxied requests
	gw          *sshgw.Gateway // the site's SSH gateway, for the federated terminal relay

	mu       sync.Mutex    // guards siteSess
	siteSess *link.Session // the current outbound link to the hub, if up
}

// currentSession returns the live hub link, or nil if the site is not linked.
func (s *Service) currentSession() *link.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.siteSess
}

func (s *Service) setSession(sess *link.Session) {
	s.mu.Lock()
	s.siteSess = sess
	s.mu.Unlock()
}

// SetGateway gives the site service its SSH gateway so a hub-proxied terminal can
// drive the same relay the local browser terminal uses.
func (s *Service) SetGateway(gw *sshgw.Gateway) {
	if s != nil {
		s.gw = gw
	}
}

// New constructs the federation service for the configured mode, or nil for
// standalone. It loads/creates identity keys as needed.
func New(deps *app.Deps) (*Service, error) {
	s := &Service{deps: deps, log: deps.Log.With("component", "federation")}
	switch {
	case deps.Cfg.IsHub():
		if err := s.ensureHubKey(context.Background()); err != nil {
			return nil, err
		}
		s.registry = link.NewRegistry()
	case deps.Cfg.IsSite():
		// Site identity is ensured lazily on first join (needs the hub reachable).
	default:
		return nil, nil // standalone
	}
	return s, nil
}

// SetSiteHandler gives the site service a reference to its own HTTP router so it
// can serve hub-proxied requests in-process. Called by the server after the
// router is built.
func (s *Service) SetSiteHandler(h http.Handler) {
	if s != nil {
		s.siteHandler = h
	}
}

// MountHub attaches hub federation routes: the site-facing link/join endpoints
// (outside /api/v1) and the operator-facing management API (inside /api/v1).
func MountHub(r chi.Router, d *app.Deps, s *Service) {
	if s == nil {
		return
	}
	// Site-facing, authenticated at the federation layer (not user sessions).
	r.Post("/federation/join", s.handleJoin)
	r.Get("/federation/link", s.handleLink)

	// Operator-facing management + read-cache, under the normal auth stack.
	r.Route("/api/v1/federation", func(pr chi.Router) {
		pr.Get("/mode", s.handleMode)
		// The terminal proxy is a WebSocket: browsers can't set an Authorization
		// header on the upgrade, so it authenticates via a ?token= query param
		// inline (like the local terminal endpoint), outside the RequireAuth group.
		pr.Get("/sites/{siteId}/terminal/{hostId}", s.handleProxyTerminal)
		pr.Group(func(ar chi.Router) {
			ar.Use(d.Auth.RequireAuth)
			ar.With(d.Auth.RequirePermission("Federation.Manage")).Get("/sites", s.handleListSites)
			ar.With(d.Auth.RequirePermission("Federation.Manage")).Post("/sites/tokens", s.handleCreateToken)
			ar.With(d.Auth.RequirePermission("Federation.Manage")).Delete("/sites/{siteId}", s.handleRevokeSite)
			ar.With(d.Auth.RequirePermission("Federation.Manage")).Post("/keys/rotate", s.handleRotateKey)
			ar.With(d.Auth.RequirePermission("Host.View")).Get("/cache/hosts", s.handleCacheHosts)
			// Generic management proxy (F4): forwards a request into the site's API.
			ar.Handle("/sites/{siteId}/proxy/*", http.HandlerFunc(s.handleProxy))
		})
	})
}

// MountSite attaches the site-side federation routes (mode probe + leave).
func MountSite(r chi.Router, d *app.Deps, s *Service) {
	if s == nil {
		return
	}
	r.Route("/api/v1/federation", func(pr chi.Router) {
		pr.Get("/mode", s.handleMode)
		pr.Group(func(ar chi.Router) {
			ar.Use(d.Auth.RequireAuth)
			ar.With(d.Auth.RequirePermission("System.Configure")).Post("/leave", s.handleLeave)
			ar.With(d.Auth.RequirePermission("System.Configure")).Post("/site/rotate-key", s.handleRotateSiteKey)
		})
	})
}

// Start launches background loops appropriate to the mode: the site maintains its
// outbound link to the hub; the hub prunes expired nonces.
func (s *Service) Start(ctx context.Context) {
	if s == nil {
		return
	}
	switch {
	case s.deps.Cfg.IsSite():
		go s.runSiteLink(ctx)
	case s.deps.Cfg.IsHub():
		go s.pruneLoop(ctx)
	}
}

func (s *Service) pruneLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.deps.Store.PruneNonces(ctx, time.Now()); err != nil {
				s.log.Warn("prune nonces", "err", err)
			}
		}
	}
}

// handleMode reports the instance's federation role to the SPA so it can show or
// hide the site dimension. Unauthenticated (no secrets; just the mode string).
func (s *Service) handleMode(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"mode": s.deps.Cfg.Mode})
}
