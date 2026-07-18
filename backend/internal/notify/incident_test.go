package notify

import "testing"

func TestMeetsMinSeverity(t *testing.T) {
	// Default (empty) min is warning: info doesn't page, warning/error do.
	if meetsMinSeverity(SeverityInfo, "") {
		t.Fatal("info should not meet the default (warning) minimum")
	}
	if !meetsMinSeverity(SeverityWarning, "") {
		t.Fatal("warning should meet the default minimum")
	}
	if !meetsMinSeverity(SeverityError, "") {
		t.Fatal("error should meet the default minimum")
	}
	// Explicit error minimum: only error pages.
	if meetsMinSeverity(SeverityWarning, SeverityError) {
		t.Fatal("warning should not meet an error minimum")
	}
	if !meetsMinSeverity(SeverityError, SeverityError) {
		t.Fatal("error should meet an error minimum")
	}
	// Info minimum: everything pages.
	if !meetsMinSeverity(SeverityInfo, SeverityInfo) {
		t.Fatal("info should meet an info minimum")
	}
}

func TestSeverityMappings(t *testing.T) {
	if pagerdutySeverity(SeverityError) != "critical" || pagerdutySeverity(SeverityWarning) != "warning" || pagerdutySeverity(SeverityInfo) != "info" {
		t.Fatal("pagerduty severity mapping wrong")
	}
	if opsgeniePriority(SeverityError) != "P1" || opsgeniePriority(SeverityWarning) != "P3" || opsgeniePriority(SeverityInfo) != "P5" {
		t.Fatal("opsgenie priority mapping wrong")
	}
}
