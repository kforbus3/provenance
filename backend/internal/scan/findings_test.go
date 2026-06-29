package scan

import "testing"

const sampleResults = `<?xml version="1.0"?>
<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2">
  <rule-result idref="xccdf_org.ssgproject.content_rule_package_rsyslog_installed" severity="medium">
    <result>pass</result>
  </rule-result>
  <rule-result idref="xccdf_org.ssgproject.content_rule_sshd_disable_root_login" severity="high">
    <result>fail</result>
  </rule-result>
  <rule-result idref="xccdf_org.ssgproject.content_rule_package_telnet_removed" severity="high">
    <result>fail</result>
  </rule-result>
  <rule-result idref="xccdf_org.ssgproject.content_rule_partition_for_tmp" severity="low">
    <result>notapplicable</result>
  </rule-result>
</TestResult>`

func TestParseFailedFindings(t *testing.T) {
	f := parseFailedFindings(sampleResults)
	if len(f) != 2 {
		t.Fatalf("failed findings = %d, want 2", len(f))
	}
	// sshd rule: failed, high, and access-impacting.
	if f[0].RuleID != "xccdf_org.ssgproject.content_rule_sshd_disable_root_login" {
		t.Fatalf("rule[0] = %q", f[0].RuleID)
	}
	if f[0].Severity != "high" || f[0].Result != "fail" {
		t.Fatalf("rule[0] sev/result = %s/%s", f[0].Severity, f[0].Result)
	}
	if !f[0].AccessImpacting {
		t.Fatalf("sshd rule should be access-impacting")
	}
	if f[0].Title != "Sshd disable root login" {
		t.Fatalf("title = %q", f[0].Title)
	}
	// telnet removal: failed but NOT access-impacting.
	if f[1].AccessImpacting {
		t.Fatalf("telnet rule should not be access-impacting")
	}
}

func TestIsAccessImpacting(t *testing.T) {
	cases := map[string]bool{
		"xccdf_org.ssgproject.content_rule_sshd_set_idle_timeout":   true,
		"xccdf_org.ssgproject.content_rule_service_nftables_enabled": true,
		"xccdf_org.ssgproject.content_rule_accounts_pam_faillock":    true,
		"xccdf_org.ssgproject.content_rule_package_rsyslog_installed": false,
		"xccdf_org.ssgproject.content_rule_sysctl_kernel_randomize":   false,
	}
	for id, want := range cases {
		if got := isAccessImpacting(id); got != want {
			t.Errorf("isAccessImpacting(%s) = %v, want %v", id, got, want)
		}
	}
}
