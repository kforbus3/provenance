package models

import (
	"time"

	"github.com/google/uuid"
)

// Network scan paths. A managed host is scanned on each it has; a range scan uses
// NetPathRange.
const (
	NetPathLAN     = "lan"     // the host's own address: what its network can reach
	NetPathOverlay = "overlay" // its overlay address: what the jump host can reach
	NetPathRange   = "range"   // an address found by scanning an operator-defined range
)

// Network scan states. NetScanUnreachable is deliberately not a kind of
// "completed": an address that did not answer was not assessed.
const (
	NetScanPending     = "pending"
	NetScanRunning     = "running"
	NetScanCompleted   = "completed"
	NetScanUnreachable = "unreachable"
	NetScanFailed      = "failed"
)

// NetScan is one address scanned from the network.
type NetScan struct {
	ID               uuid.UUID      `json:"id"`
	RunID            uuid.UUID      `json:"runId"`
	HostID           *uuid.UUID     `json:"hostId,omitempty"`
	Hostname         string         `json:"hostname,omitempty"`
	RangeID          *uuid.UUID     `json:"rangeId,omitempty"`
	RangeName        string         `json:"rangeName,omitempty"`
	Target           string         `json:"target"`
	Path             string         `json:"path"`
	Requester        string         `json:"requester"`
	Scheduled        bool           `json:"scheduled"`
	Status           string         `json:"status"`
	Error            string         `json:"error,omitempty"`
	Reason           string         `json:"reason,omitempty"`
	TemplatesVersion string         `json:"templatesVersion,omitempty"`
	OpenPorts        int            `json:"openPorts"`
	Total            int            `json:"total"`
	Critical         int            `json:"critical"`
	High             int            `json:"high"`
	Medium           int            `json:"medium"`
	Low              int            `json:"low"`
	Unexpected       int            `json:"unexpected"`
	Listeners        []NetListener  `json:"listeners,omitempty"`
	ListenersKnown   bool           `json:"listenersKnown"`
	Warnings         []string       `json:"warnings,omitempty"`
	DurationSec      float64        `json:"durationSec"`
	StartedAt        *time.Time     `json:"startedAt,omitempty"`
	FinishedAt       *time.Time     `json:"finishedAt,omitempty"`
	CreatedAt        time.Time      `json:"createdAt"`
	Services         []NetService   `json:"services,omitempty"`
	Findings         []NetFinding   `json:"findings,omitempty"`
	Detections       []NetDetection `json:"-"`
}

// NetListener is one socket a host reported having bound, with what owns it.
//
// Package and LibPackages are what join the network view to grype's: a CVE in a
// package that owns -- or is loaded by -- a process listening on a reachable port is
// exposed in a way the same CVE in an idle library is not.
type NetListener struct {
	Proto       string   `json:"proto"`
	Address     string   `json:"address"`
	Port        int      `json:"port"`
	Process     string   `json:"process,omitempty"`
	PID         int      `json:"pid,omitempty"`
	Exe         string   `json:"exe,omitempty"`
	Package     string   `json:"package,omitempty"`
	LibPackages []string `json:"libPackages,omitempty"`
	// Exposed: bound to something other than loopback.
	Exposed bool `json:"exposed"`
}

// NetService is what answered on one port.
type NetService struct {
	Port       int            `json:"port"`
	Proto      string         `json:"proto"`
	Service    string         `json:"service,omitempty"`
	Product    string         `json:"product,omitempty"`
	Version    string         `json:"version,omitempty"`
	TLS        bool           `json:"tls"`
	CPEs       []string       `json:"cpes,omitempty"`
	Detections []NetDetection `json:"detections,omitempty"`
	Process    string         `json:"process,omitempty"`
	// Unexpected: reachable, but the host's own listener list has no socket on this
	// port. Only ever set when that list was collected.
	Unexpected bool `json:"unexpected"`
}

// NetDetection is a fact about a service that is not a problem with it.
type NetDetection struct {
	TemplateID string `json:"templateId"`
	Name       string `json:"name"`
	Port       int    `json:"port,omitempty"`
}

// NetFinding is a vulnerability or misconfiguration observed from the network.
type NetFinding struct {
	ID          uuid.UUID `json:"id"`
	TemplateID  string    `json:"templateId"`
	Name        string    `json:"name"`
	Severity    string    `json:"severity"`
	Port        int       `json:"port"`
	Proto       string    `json:"proto"`
	MatchedAt   string    `json:"matchedAt,omitempty"`
	CVEs        []string  `json:"cves,omitempty"`
	CWEs        []string  `json:"cwes,omitempty"`
	CVSSScore   float64   `json:"cvssScore"`
	CVSSVector  string    `json:"cvssVector,omitempty"`
	Description string    `json:"description,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	References  []string  `json:"references,omitempty"`
	Extracted   []string  `json:"extracted,omitempty"`
	Tags        []string  `json:"tags,omitempty"`
	// Corroboration with the host's grype scan, computed at read time (Phase 2):
	//   "confirmed"   the package scan reports the same CVE on this host
	//   "banner-only" the CVE was matched from a version banner and the package scan,
	//                 which knows the real (possibly backported) version, does not
	//                 report it -- likely a false positive on a patched distro build
	// Empty when the finding carries no CVE or the host has no package scan.
	Corroboration string `json:"corroboration,omitempty"`
}

// NetScanRange is an operator-defined network range to scan for unmanaged devices.
type NetScanRange struct {
	ID        uuid.UUID  `json:"id"`
	Name      string     `json:"name"`
	CIDR      string     `json:"cidr"`
	Note      string     `json:"note"`
	Enabled   bool       `json:"enabled"`
	CreatedAt time.Time  `json:"createdAt"`
	LastScan  *time.Time `json:"lastScan,omitempty"`
	// Addresses found live on the last scan.
	LastLive int `json:"lastLive"`
}

// NetExposure is the network-side annotation on a grype finding (Phase 2): the
// vulnerable package owns, or is loaded by, a process listening on a port that a
// network scan reached.
type NetExposure struct {
	// The first reachable endpoint found, for a one-line summary.
	Port    int    `json:"port"`
	Proto   string `json:"proto"`
	Process string `json:"process,omitempty"`
	// Every reachable endpoint, as "443/tcp nginx (lan)". A library is often loaded by
	// several listening processes; each is a way in.
	Endpoints []string `json:"endpoints,omitempty"`
	Paths     []string `json:"paths"`            // lan / overlay
	Via       string   `json:"via"`              // "binary" (owns the process), "library" (loaded by it) or "network"
	Network   bool     `json:"networkConfirmed"` // a network check reported the same CVE here
}
