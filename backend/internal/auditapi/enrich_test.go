package auditapi

import (
	"testing"

	"github.com/kforbus3/Moorgate/backend/internal/models"
)

func TestApplyEntityNamesResolvesTargetAndDetail(t *testing.T) {
	const (
		userID = "ac58c87c-df7d-4339-b824-f6e80d3847f2"
		hostID = "db60ac96-f240-4e8e-829a-1880c7fa7c03"
		jobID  = "00000000-0000-0000-0000-000000000123"
	)
	names := map[string]string{userID: "alice", hostID: "web-01"}
	resolve := func(s string) string { return names[s] }

	events := []models.AuditEvent{{
		Action:     "user.host_access_revoke",
		TargetKind: "user",
		TargetID:   userID,
		Detail:     map[string]any{"hostId": hostID, "jobId": jobID, "reason": "cleanup"},
	}}
	applyEntityNames(events, resolve)

	if events[0].TargetName != "alice" {
		t.Errorf("target not resolved: TargetName=%q", events[0].TargetName)
	}
	if events[0].Detail["hostId"] != "web-01" {
		t.Errorf("host uuid in detail not resolved: %v", events[0].Detail["hostId"])
	}
	// A UUID that resolves to nothing (a job id) must be left untouched, as must
	// non-UUID values.
	if events[0].Detail["jobId"] != jobID {
		t.Errorf("unknown uuid should be left as-is: %v", events[0].Detail["jobId"])
	}
	if events[0].Detail["reason"] != "cleanup" {
		t.Errorf("non-uuid value should be untouched: %v", events[0].Detail["reason"])
	}
}

func TestApplyEntityNamesKeepsExistingTargetName(t *testing.T) {
	events := []models.AuditEvent{{
		TargetKind: "user",
		TargetID:   "ac58c87c-df7d-4339-b824-f6e80d3847f2",
		TargetName: "already-set",
	}}
	applyEntityNames(events, func(string) string { return "other" })
	if events[0].TargetName != "already-set" {
		t.Errorf("existing TargetName was overwritten: %q", events[0].TargetName)
	}
}
