package k8sbroker

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func review(verb, resource, sub, namespace string) []byte {
	b, _ := json.Marshal(map[string]any{
		"spec": map[string]any{"resourceAttributes": map[string]any{
			"verb": verb, "resource": resource, "subresource": sub, "namespace": namespace,
		}},
	})
	return b
}

func allowedResponse(allowed bool) *http.Response {
	body, _ := json.Marshal(map[string]any{
		"kind": "SelfSubjectAccessReview", "apiVersion": "authorization.k8s.io/v1",
		"status": map[string]any{"allowed": allowed},
	})
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

func decide(t *testing.T, resp *http.Response) accessReview {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out accessReview
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return out
}

// The button has to disappear, not fail on click.
//
// Headlamp asks the cluster what it may do, and the cluster answers for the
// registered ServiceAccount -- which on a cluster joined at `administer` is
// cluster-admin. Left alone, a read-only Provenance user is offered every
// destructive control and each one is then refused by the broker. An operator
// cannot tell that from a broken console.
func TestAReadOnlyUserIsNotOfferedWritesTheClusterWouldAllow(t *testing.T) {
	readOnly := func(p string) bool { return p == permAccess }

	for _, c := range []struct{ verb, resource, sub, ns string }{
		{"delete", "pods", "", "default"},
		{"patch", "deployments", "scale", "default"},
		{"create", "namespaces", "", ""},
		{"get", "secrets", "", "default"},
		{"create", "pods", "exec", "default"},
	} {
		resp := allowedResponse(true) // the cluster says yes
		if err := filterAccessReview(readOnly, review(c.verb, c.resource, c.sub, c.ns), resp); err != nil {
			t.Fatalf("filter: %v", err)
		}
		got := decide(t, resp)
		if got.Status.Allowed {
			t.Errorf("%s %s%s still offered to a read-only user", c.verb, c.resource, c.sub)
		}
		if got.Status.Reason == "" {
			t.Errorf("%s %s denied with no reason — the operator cannot tell this from a bug",
				c.verb, c.resource)
		}
	}
}

// Reads must survive the filter, or the console goes blank for the very users
// this is meant to keep it working for.
func TestAReadOnlyUserKeepsEveryRead(t *testing.T) {
	readOnly := func(p string) bool { return p == permAccess }
	for _, c := range []struct{ verb, resource, sub, ns string }{
		{"get", "pods", "", "default"},
		{"list", "deployments", "", "default"},
		{"watch", "events", "", "default"},
		{"get", "pods", "log", "default"},
		{"list", "namespaces", "", ""},
		{"list", "nodes", "", ""},
	} {
		resp := allowedResponse(true)
		if err := filterAccessReview(readOnly, review(c.verb, c.resource, c.sub, c.ns), resp); err != nil {
			t.Fatalf("filter: %v", err)
		}
		if !decide(t, resp).Status.Allowed {
			t.Errorf("%s %s%s was taken away from a read-only user", c.verb, c.resource, c.sub)
		}
	}
}

// Provenance can only ever narrow. A permission in Provenance cannot conjure
// access the cluster withholds -- that would put back a button that fails,
// just at the cluster instead.
func TestTheFilterNeverWidensWhatTheClusterDenied(t *testing.T) {
	admin := func(string) bool { return true }
	resp := allowedResponse(false) // the cluster says no
	if err := filterAccessReview(admin, review("create", "namespaces", "", ""), resp); err != nil {
		t.Fatalf("filter: %v", err)
	}
	if decide(t, resp).Status.Allowed {
		t.Error("a cluster denial was turned into an allow")
	}
}

func TestAnOperatorIsOfferedWorkloadsButNotTheCluster(t *testing.T) {
	operator := func(p string) bool { return p == permAccess || p == permOperate }

	resp := allowedResponse(true)
	_ = filterAccessReview(operator, review("delete", "pods", "", "default"), resp)
	if !decide(t, resp).Status.Allowed {
		t.Error("an operator was not offered deleting a pod")
	}

	for _, c := range []struct{ verb, resource, ns string }{
		{"create", "namespaces", ""},
		{"create", "clusterrolebindings", ""},
		{"get", "secrets", "default"},
	} {
		resp := allowedResponse(true)
		_ = filterAccessReview(operator, review(c.verb, c.resource, "", c.ns), resp)
		if decide(t, resp).Status.Allowed {
			t.Errorf("an operator was offered %s %s", c.verb, c.resource)
		}
	}
}

// The rules review drives whole screens, so a write verb left in it puts a
// control on screen that the broker refuses.
func TestRulesReviewDropsVerbsTheRoleLacks(t *testing.T) {
	readOnly := func(p string) bool { return p == permAccess }
	body, _ := json.Marshal(map[string]any{
		"status": map[string]any{"resourceRules": []any{
			map[string]any{
				"apiGroups": []any{""}, "resources": []any{"pods"},
				"verbs": []any{"get", "list", "watch", "create", "delete"},
			},
			map[string]any{
				"apiGroups": []any{""}, "resources": []any{"secrets"},
				"verbs": []any{"get", "list"},
			},
		}},
	})
	resp := &http.Response{
		StatusCode: 200, Header: http.Header{},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	if err := filterRulesReview(readOnly, resp); err != nil {
		t.Fatalf("filter: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out rulesReview
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Status.ResourceRules) != 2 {
		t.Fatalf("rules = %d, want 2", len(out.Status.ResourceRules))
	}
	pods := out.Status.ResourceRules[0].Verbs
	for _, v := range pods {
		if v == "create" || v == "delete" {
			t.Errorf("pods kept %q for a read-only user: %v", v, pods)
		}
	}
	if len(pods) != 3 {
		t.Errorf("pods verbs = %v, want the three reads", pods)
	}
	// Secrets are Administer even to read, so a read-only user keeps nothing.
	if got := out.Status.ResourceRules[1].Verbs; len(got) != 0 {
		t.Errorf("secrets verbs = %v, want none for a read-only user", got)
	}
}

// The rewritten body has to be self-consistent, or the client hangs waiting for
// bytes that never come.
func TestTheRewrittenBodyHasAMatchingLength(t *testing.T) {
	resp := allowedResponse(true)
	resp.Header.Set("Content-Length", "999")
	_ = filterAccessReview(func(string) bool { return false },
		review("delete", "pods", "", "default"), resp)
	raw, _ := io.ReadAll(resp.Body)
	if resp.ContentLength != int64(len(raw)) {
		t.Errorf("ContentLength = %d, body = %d", resp.ContentLength, len(raw))
	}
	if got := resp.Header.Get("Content-Length"); got != itoa(len(raw)) {
		t.Errorf("Content-Length header = %s, body = %d", got, len(raw))
	}
}

// The filter must not touch anything else -- above all not a watch, which must
// keep streaming.
func TestOnlySelfReviewsAreIntercepted(t *testing.T) {
	has := func(string) bool { return true }
	for _, path := range []string{
		"/api/v1/namespaces/default/pods?watch=true",
		"/api/v1/namespaces/default/pods/web-1/log",
		"/apis/apps/v1/namespaces/default/deployments",
	} {
		if f := reviewIntersector(has, path, nil); f != nil {
			t.Errorf("%s would be buffered and rewritten", path)
		}
	}
	if f := reviewIntersector(has,
		"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", review("get", "pods", "", "d")); f == nil {
		t.Error("a self-review was not intercepted")
	}
}
