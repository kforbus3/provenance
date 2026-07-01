package scan

import (
	"encoding/xml"
	"strings"

	"github.com/fleet-terminal/backend/internal/models"
)

// accessImpactingTokens flags rules whose remediation could sever Fleet's own
// access to the host (SSH, the WireGuard/firewall path, or account lockout).
// Matched as case-insensitive substrings of the rule id.
//
// The ip_forward/rp_filter/route_localnet/send_redirects/ip_local_port_range
// tokens catch the kernel networking sysctls that break Fleet's own reachability
// on a routed deployment: disabling IP forwarding or tightening reverse-path
// filtering severs Docker's bridge networking (which serves the web UI) and the
// jump-host WireGuard routing path. Tokens stay specific so unrelated sysctls
// (e.g. sysctl_kernel_*) are not falsely flagged.
//
// The sudo/root_login tokens catch fixes that break Fleet's own privilege path:
// enrollment and remediation run non-interactive `sudo bash` as the fleet user,
// so `Defaults noexec`/`requiretty` (sudo_*) or disabling direct/root login
// (no_direct_root_logins, sshd_*_root_login) can stop Fleet automating the host.
var accessImpactingTokens = []string{
	"sshd", "ssh_", "_ssh", "firewall", "firewalld", "nftables", "iptables",
	"ufw", "_pam_", "faillock", "tally", "lockout", "wireless", "network_",
	"ip_forward", "rp_filter", "route_localnet", "send_redirects", "ip_local_port_range",
	"sudo", "root_login",
}

// parseFailedFindings extracts failed rules from an XCCDF results document.
// Robust to namespaces/formatting (token-based). Titles are derived from the
// rule id (full titles live in the HTML report).
func parseFailedFindings(resultsXML string) []models.ScanFinding {
	dec := xml.NewDecoder(strings.NewReader(resultsXML))
	var out []models.ScanFinding
	var cur *models.ScanFinding
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "rule-result":
				f := models.ScanFinding{}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "idref":
						f.RuleID = a.Value
					case "severity":
						f.Severity = a.Value
					}
				}
				cur = &f
			case "result":
				if cur != nil {
					var val string
					if err := dec.DecodeElement(&val, &t); err == nil {
						cur.Result = strings.TrimSpace(val)
						if cur.Result == "fail" && cur.RuleID != "" {
							cur.Title = prettifyRuleID(cur.RuleID)
							cur.AccessImpacting = isAccessImpacting(cur.RuleID)
							out = append(out, *cur)
						}
					}
					cur = nil
				}
			}
		}
	}
	return out
}

// prettifyRuleID turns an SSG rule id into a readable label.
func prettifyRuleID(id string) string {
	s := id
	if i := strings.LastIndex(s, "_rule_"); i >= 0 {
		s = s[i+len("_rule_"):]
	}
	s = strings.ReplaceAll(s, "_", " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return id
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func isAccessImpacting(id string) bool {
	low := strings.ToLower(id)
	for _, tok := range accessImpactingTokens {
		if strings.Contains(low, tok) {
			return true
		}
	}
	return false
}
