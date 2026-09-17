package k8sbroker

import "testing"

func statusFor(t *testing.T, body string) string {
	t.Helper()
	rows := simplifyList([]byte(body))
	if len(rows) != 1 {
		t.Fatalf("parsed %d rows, want 1", len(rows))
	}
	return rows[0]["status"].(string)
}

// The bug: this view read only status.phase, which pods have and nodes do not,
// so every node showed a blank status — indistinguishable from "we could not
// tell" on the one screen whose job is telling you.
func TestANodeReportsItsReadiness(t *testing.T) {
	ready := `{"items":[{"metadata":{"name":"k3s"},"status":{"conditions":[
		{"type":"MemoryPressure","status":"False"},{"type":"Ready","status":"True"}]}}]}`
	if got := statusFor(t, ready); got != "Ready" {
		t.Errorf("status = %q, want Ready", got)
	}
	notReady := `{"items":[{"metadata":{"name":"k3s"},"status":{"conditions":[
		{"type":"Ready","status":"False"}]}}]}`
	if got := statusFor(t, notReady); got != "NotReady" {
		t.Errorf("status = %q, want NotReady", got)
	}
}

// A cordoned node is Ready by every other measure and runs nothing new. Showing
// it as plain "Ready" hides the reason somebody is looking at the column.
func TestACordonedNodeSaysSo(t *testing.T) {
	body := `{"items":[{"metadata":{"name":"k3s"},"spec":{"unschedulable":true},
		"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}`
	if got := statusFor(t, body); got != "Ready,SchedulingDisabled" {
		t.Errorf("status = %q, want Ready,SchedulingDisabled", got)
	}
}

// Deployments carry a count, not a word, and were also blank.
func TestAWorkloadReportsReadyOverDesired(t *testing.T) {
	body := `{"items":[{"metadata":{"name":"web"},"status":{"replicas":3,"readyReplicas":2}}]}`
	if got := statusFor(t, body); got != "2/3" {
		t.Errorf("status = %q, want 2/3", got)
	}
	// Scaled to zero is a real, deliberate state; 0/0 must not read as unknown.
	zero := `{"items":[{"metadata":{"name":"web"},"status":{"replicas":0}}]}`
	if got := statusFor(t, zero); got != "0/0" {
		t.Errorf("status = %q, want 0/0", got)
	}
	// No ready replicas at all is 0/N, not blank.
	none := `{"items":[{"metadata":{"name":"web"},"status":{"replicas":2}}]}`
	if got := statusFor(t, none); got != "0/2" {
		t.Errorf("status = %q, want 0/2", got)
	}
}

func TestPodsAndNamespacesStillUseTheirPhase(t *testing.T) {
	pod := `{"items":[{"metadata":{"name":"p","namespace":"default"},"status":{"phase":"Running"}}]}`
	if got := statusFor(t, pod); got != "Running" {
		t.Errorf("pod status = %q, want Running", got)
	}
	ns := `{"items":[{"metadata":{"name":"kube-system"},"status":{"phase":"Active"}}]}`
	if got := statusFor(t, ns); got != "Active" {
		t.Errorf("namespace status = %q, want Active", got)
	}
}

// A Service has no status. Left empty on purpose so the UI can say so rather
// than this inventing a word for it.
func TestAStatuslessObjectStaysEmpty(t *testing.T) {
	body := `{"items":[{"metadata":{"name":"svc","namespace":"default"},"spec":{"type":"ClusterIP"}}]}`
	if got := statusFor(t, body); got != "" {
		t.Errorf("status = %q, want empty", got)
	}
}
