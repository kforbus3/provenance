// Package metrics exposes Prometheus collectors for the application.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTPRequests counts HTTP requests by method, route, and status.
	HTTPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prov_http_requests_total",
		Help: "Total HTTP requests processed.",
	}, []string{"method", "route", "status"})

	// HTTPDuration observes request latency.
	HTTPDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "prov_http_request_duration_seconds",
		Help:    "HTTP request latency in seconds.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "route"})

	// ActiveSSHSessions tracks currently-open SSH terminal sessions.
	ActiveSSHSessions = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "prov_active_ssh_sessions",
		Help: "Number of active SSH terminal sessions.",
	})

	// CertificatesIssued counts SSH certificates issued by kind.
	CertificatesIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prov_certificates_issued_total",
		Help: "Total SSH certificates issued.",
	}, []string{"kind"})

	// AuditWriteFailures counts audit-chain appends that failed.
	//
	// This exists because the hash chain cannot reveal a dropped event. Verification
	// detects MODIFICATION -- an altered row no longer matches its hash -- but a write
	// that never landed leaves no gap, because the next row chains from the last one
	// that succeeded. So a database hiccup can make a session start, a credential
	// issuance or a login vanish in a way VerifyAuditChain can never see.
	//
	// A counter is the only thing that can surface that. Alert on any increase.
	AuditWriteFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prov_audit_write_failures_total",
		Help: "Audit-chain appends that failed. The chain cannot show these as gaps; alert on any increase.",
	}, []string{"action"})

	// SessionsUnrecorded counts privileged sessions that proceeded without a recording.
	//
	// Only reachable when an operator has explicitly allowed it; the default is to
	// refuse the session instead.
	SessionsUnrecorded = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "prov_sessions_unrecorded_total",
		Help: "Privileged sessions that proceeded with no session recording.",
	}, []string{"protocol", "reason"})

	// HostsByStatus reflects host health counts.
	HostsByStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "prov_hosts_status",
		Help: "Number of hosts by status.",
	}, []string{"status"})
)
