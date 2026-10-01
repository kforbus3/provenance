package netscan

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// sidecarResult is the net-scanner's /scan response.
type sidecarResult struct {
	Target      string           `json:"target"`
	Reachable   bool             `json:"reachable"`
	Reason      string           `json:"reason"`
	OpenPorts   []int            `json:"openPorts"`
	Services    []sidecarService `json:"services"`
	Findings    []sidecarFinding `json:"findings"`
	Detections  []sidecarFinding `json:"detections"`
	Templates   map[string]any   `json:"templates"`
	Errors      []string         `json:"errors"`
	DurationSec float64          `json:"durationSec"`
}

type sidecarService struct {
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	Service string   `json:"service"`
	Product string   `json:"product"`
	Version string   `json:"version"`
	TLS     bool     `json:"tls"`
	CPEs    []string `json:"cpes"`
}

type sidecarFinding struct {
	TemplateID  string   `json:"templateId"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Port        int      `json:"port"`
	Proto       string   `json:"proto"`
	MatchedAt   string   `json:"matchedAt"`
	CVEs        []string `json:"cves"`
	CWEs        []string `json:"cwes"`
	CVSS        float64  `json:"cvss"`
	CVSSVector  string   `json:"cvssVector"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	References  []string `json:"references"`
	Extracted   []string `json:"extracted"`
	Tags        []string `json:"tags"`
}

func (r *sidecarResult) templatesVersion() string {
	if r.Templates == nil {
		return ""
	}
	v, _ := r.Templates["version"].(string)
	return v
}

// udpServiceNames names the UDP services the scanner probes, for a port that only
// appears because a UDP check found something there.
var udpServiceNames = map[int]string{
	53: "dns", 69: "tftp", 123: "ntp", 137: "netbios-ns", 161: "snmp", 623: "ipmi",
	1434: "mssql-browser", 1900: "ssdp", 5353: "mdns",
}

// merge combines what the network reached with what the host says it has bound.
//
// listeners is nil when the host's own list could not be collected. Then nothing
// is marked unexpected: absence from a list nobody has is not evidence of anything.
func merge(res *sidecarResult, listeners []models.NetListener) ([]models.NetService, []models.NetFinding) {
	type key struct {
		proto string
		port  int
	}
	byKey := map[key]*models.NetService{}
	var order []key

	add := func(k key, s models.NetService) *models.NetService {
		if existing, ok := byKey[k]; ok {
			return existing
		}
		cp := s
		byKey[k] = &cp
		order = append(order, k)
		return &cp
	}

	for _, s := range res.Services {
		proto := strings.ToLower(s.Proto)
		if proto == "" {
			proto = "tcp"
		}
		add(key{proto, s.Port}, models.NetService{
			Port: s.Port, Proto: proto, Service: s.Service, Product: s.Product,
			Version: s.Version, TLS: s.TLS, CPEs: s.CPEs,
		})
	}
	for _, p := range res.OpenPorts {
		add(key{"tcp", p}, models.NetService{Port: p, Proto: "tcp"})
	}

	findings := make([]models.NetFinding, 0, len(res.Findings))
	for _, f := range res.Findings {
		proto := strings.ToLower(f.Proto)
		if proto == "" {
			proto = "tcp"
		}
		if f.Port > 0 && proto == "udp" {
			add(key{"udp", f.Port}, models.NetService{Port: f.Port, Proto: "udp", Service: udpServiceNames[f.Port]})
		}
		findings = append(findings, models.NetFinding{
			TemplateID: f.TemplateID, Name: f.Name, Severity: strings.ToLower(f.Severity),
			Port: f.Port, Proto: proto, MatchedAt: f.MatchedAt, CVEs: upper(f.CVEs), CWEs: upper(f.CWEs),
			CVSSScore: f.CVSS, CVSSVector: f.CVSSVector, Description: f.Description,
			Remediation: f.Remediation, References: f.References, Extracted: f.Extracted, Tags: f.Tags,
		})
	}
	for _, d := range res.Detections {
		proto := strings.ToLower(d.Proto)
		if proto == "" {
			proto = "tcp"
		}
		if s, ok := byKey[key{proto, d.Port}]; ok {
			s.Detections = append(s.Detections, models.NetDetection{TemplateID: d.TemplateID, Name: d.Name, Port: d.Port})
		}
	}

	if listeners != nil {
		for _, k := range order {
			s := byKey[k]
			if l := listenerFor(listeners, k.proto, k.port); l != nil {
				s.Process = l.Process
			} else {
				s.Unexpected = true
			}
		}
	}

	sort.Slice(order, func(i, j int) bool {
		if order[i].proto != order[j].proto {
			return order[i].proto < order[j].proto
		}
		return order[i].port < order[j].port
	})
	services := make([]models.NetService, 0, len(order))
	for _, k := range order {
		services = append(services, *byKey[k])
	}
	return services, findings
}

// listenerFor finds the host's socket for a reachable port. Only a non-loopback
// binding explains it: a socket bound to loopback alone that nevertheless answers
// from the network is being reached through something -- a port forward, a NAT
// rule -- and that is exactly what Unexpected exists to surface.
func listenerFor(ls []models.NetListener, proto string, port int) *models.NetListener {
	for i := range ls {
		if l := &ls[i]; l.Proto == proto && l.Port == port && l.Exposed {
			return l
		}
	}
	return nil
}

func upper(v []string) []string {
	out := make([]string, 0, len(v))
	for _, s := range v {
		out = append(out, strings.ToUpper(s))
	}
	return out
}

// unexpectedWarning explains a scan whose services include ports the host does not
// account for.
func unexpectedWarning(services []models.NetService) string {
	var ports []string
	for _, s := range services {
		if s.Unexpected {
			ports = append(ports, fmt.Sprintf("%d/%s", s.Port, s.Proto))
		}
	}
	if len(ports) == 0 {
		return ""
	}
	return fmt.Sprintf("Reachable but not in the host's own listener list: %s. Usually a port forward or "+
		"NAT rule (Docker with userland-proxy disabled publishes ports this way); otherwise something on "+
		"the host is answering without showing in ss.", strings.Join(ports, ", "))
}
