package k8sbroker

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// Making Headlamp's UI reflect the PERSON, not the ServiceAccount.
//
// Headlamp decides which buttons to render by asking the cluster what it may do
// -- SelfSubjectAccessReview before an action, SelfSubjectRulesReview for a
// whole screen. It asks as the registered ServiceAccount, because that is the
// only identity the cluster has for us. So on a cluster joined at `administer`,
// a read-only Provenance user is shown every destructive button the cluster
// allows, and every one of them fails at Provenance's own authorization check.
//
// Buttons that exist and then refuse are worse than absent buttons: the operator
// cannot tell a permission boundary from a broken console, which is precisely
// the confusion that "why can I not create a namespace" came out of.
//
// Provenance is answering these questions about a caller it knows, so it
// intersects the cluster's answer with the caller's Provenance permissions on
// the way back. Headlamp then hides what the person may not do, using its own
// existing mechanism and no plugin.
//
// This is not the enforcement -- authorize() in the proxy path is, and it runs
// whether or not anything was ever reviewed. This only keeps the UI honest.

// reviewIntersector rewrites self-review responses to the intersection of what
// the cluster allows and what this caller's Provenance role allows.
//
// Returns nil when the request is not a self-review, so the ordinary path stays
// untouched -- a watch must not be buffered to be inspected.
func reviewIntersector(has func(string) bool, path string, body []byte) func(*http.Response) error {
	resource, _, _ := parseAPIPath(path)
	switch resource {
	case "selfsubjectaccessreviews":
		return func(resp *http.Response) error { return filterAccessReview(has, body, resp) }
	case "selfsubjectrulesreviews":
		return func(resp *http.Response) error { return filterRulesReview(has, resp) }
	}
	return nil
}

// accessReview is the slice of SelfSubjectAccessReview this needs.
type accessReview struct {
	Spec struct {
		ResourceAttributes *struct {
			Namespace   string `json:"namespace"`
			Verb        string `json:"verb"`
			Group       string `json:"group"`
			Resource    string `json:"resource"`
			Subresource string `json:"subresource"`
		} `json:"resourceAttributes"`
	} `json:"spec"`
	Status struct {
		Allowed bool   `json:"allowed"`
		Denied  bool   `json:"denied"`
		Reason  string `json:"reason"`
	} `json:"status"`
}

// filterAccessReview turns an allowed review into a denied one when Provenance
// would refuse the reviewed action.
//
// Only ever narrows: a review the cluster denied stays denied. Provenance's
// permissions cannot grant access the cluster withholds, and pretending
// otherwise would produce a button that fails at the cluster instead.
func filterAccessReview(has func(string) bool, reqBody []byte, resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	var req accessReview
	if err := json.Unmarshal(reqBody, &req); err != nil || req.Spec.ResourceAttributes == nil {
		return nil // not a resource review (a nonResourceAttributes one), leave it
	}
	ra := req.Spec.ResourceAttributes
	if allowedByProvenance(has, ra.Verb, ra.Resource, ra.Subresource, ra.Namespace != "") {
		return nil
	}

	var out accessReview
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil // unparseable: pass it through rather than break the console
	}
	if !out.Status.Allowed {
		return replaceBody(resp, raw) // already denied; nothing to narrow
	}
	// Rewrite the decision in the original document so nothing else about it is
	// lost, rather than emitting a synthesised reply.
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return replaceBody(resp, raw)
	}
	status, _ := doc["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
		doc["status"] = status
	}
	status["allowed"] = false
	status["reason"] = "not permitted by your Provenance role (" +
		requiredPermissionFor(ra.Verb, ra.Resource, ra.Subresource, ra.Namespace != "") + ")"
	next, err := json.Marshal(doc)
	if err != nil {
		return replaceBody(resp, raw)
	}
	return replaceBody(resp, next)
}

// rulesReview is the slice of SelfSubjectRulesReview this needs.
type rulesReview struct {
	Status struct {
		ResourceRules []struct {
			Verbs         []string `json:"verbs"`
			APIGroups     []string `json:"apiGroups"`
			Resources     []string `json:"resources"`
			ResourceNames []string `json:"resourceNames"`
		} `json:"resourceRules"`
	} `json:"status"`
}

// filterRulesReview drops verbs the caller's Provenance role does not carry.
//
// Headlamp uses this for whole sections of its UI, so a rule left claiming
// "delete" on secrets puts a delete control on screen that Provenance refuses.
func filterRulesReview(has func(string) bool, resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil
	}
	raw, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return replaceBody(resp, raw)
	}
	status, _ := doc["status"].(map[string]any)
	rules, _ := status["resourceRules"].([]any)
	if rules == nil {
		return replaceBody(resp, raw)
	}
	for _, r := range rules {
		rule, _ := r.(map[string]any)
		if rule == nil {
			continue
		}
		verbs, _ := rule["verbs"].([]any)
		resources, _ := rule["resources"].([]any)
		var kept []any
		for _, v := range verbs {
			verb, _ := v.(string)
			if verbAllowedForAny(has, verb, resources) {
				kept = append(kept, v)
			}
		}
		if kept == nil {
			kept = []any{}
		}
		rule["verbs"] = kept
	}
	next, err := json.Marshal(doc)
	if err != nil {
		return replaceBody(resp, raw)
	}
	return replaceBody(resp, next)
}

// verbAllowedForAny keeps a verb if it is permitted on any resource the rule
// names. A rule covering several resources is kept when the verb is usable on
// one of them, because dropping it would hide the ones it IS usable on.
func verbAllowedForAny(has func(string) bool, verb string, resources []any) bool {
	if len(resources) == 0 {
		return allowedByProvenance(has, verb, "", "", false)
	}
	for _, r := range resources {
		res, _ := r.(string)
		name, sub := res, ""
		if i := strings.Index(res, "/"); i >= 0 {
			name, sub = res[:i], res[i+1:]
		}
		// A wildcard rule is the cluster saying "anything"; judge it on the verb.
		if name == "*" {
			name = ""
		}
		if allowedByProvenance(has, verb, name, sub, true) {
			return true
		}
	}
	return false
}

// allowedByProvenance answers the review questions in the same terms
// requiredPermission answers request paths, so the UI and the enforcement cannot
// disagree about what a role may do.
func allowedByProvenance(has func(string) bool, verb, resource, sub string, namespaced bool) bool {
	return has(requiredPermissionFor(verb, resource, sub, namespaced))
}

// requiredPermissionFor is requiredPermission expressed over a review's fields
// rather than a URL path. One function would be better than two; a review gives
// a verb where a request gives a method, and translating a verb into a fake
// method to reuse the other reads worse than sharing the tables.
func requiredPermissionFor(verb, resource, sub string, namespaced bool) string {
	if resource == "secrets" {
		return permAdminister
	}
	if reviewResources[resource] {
		return permAccess
	}
	switch sub {
	case "exec", "attach", "portforward", "proxy", "eviction":
		return permOperate
	}
	switch verb {
	case "get", "list", "watch":
		return permAccess
	}
	if administerResources[resource] {
		return permAdminister
	}
	if namespaced {
		return permOperate
	}
	return permAdminister
}

// replaceBody swaps a response's body for bytes already in hand, fixing the
// length headers so the client is not left waiting for content that will not
// arrive.
func replaceBody(resp *http.Response, body []byte) error {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", itoa(len(body)))
	resp.Header.Del("Content-Encoding") // we are handing back plain JSON
	return nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
