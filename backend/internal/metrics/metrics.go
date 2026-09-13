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

	// HostsByStatus reflects host health counts.
	HostsByStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "prov_hosts_status",
		Help: "Number of hosts by status.",
	}, []string{"status"})
)
