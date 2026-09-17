package k8sbroker

import (
	"net/http"
	"strings"
)

// What a person may do to a cluster is decided by their PROVENANCE role, not by
// the cluster's ServiceAccount.
//
// Every operator reaches a cluster through one registered credential, so the
// cluster cannot tell them apart: to it, every request is the same
// ServiceAccount. Left there, "who may delete this deployment" is answered by
// whatever RBAC was applied when the cluster was joined, identically for
// everyone holding Kubernetes.Access -- an admin and a read-only operator alike.
//
// Provenance is in the middle of every call, so it is the only place that CAN
// tell them apart, and therefore the place that has to decide. The cluster
// grants the capability; Provenance decides who may use it. That also settles
// what to grant on the cluster: a fully capable ServiceAccount stops being a
// blanket handout, because reaching it still requires the matching Provenance
// permission.
//
// Three permissions, mapping onto the three onboarding levels so the two models
// do not need reconciling in somebody's head:
//
//	Kubernetes.Access     — read. Browse, diagnose, follow logs.
//	Kubernetes.Operate    — workload lifecycle: pods, deployments, jobs, services.
//	Kubernetes.Administer — the cluster itself: namespaces, CRDs, RBAC, storage,
//	                        nodes, and Secrets (read as well as write).
const (
	permAccess     = "Kubernetes.Access"
	permOperate    = "Kubernetes.Operate"
	permAdminister = "Kubernetes.Administer"
)

// administerResources are the resources whose modification IS administering the
// cluster rather than running something on it.
//
// Cluster-scoped, or namespaced but able to grant authority (RBAC, service
// accounts) or hold credentials (secrets).
var administerResources = map[string]bool{
	// Identity and authority. Creating any of these is a route to permissions
	// the creator was not given.
	"serviceaccounts":     true,
	"roles":               true,
	"rolebindings":        true,
	"clusterroles":        true,
	"clusterrolebindings": true,
	// Credentials. Note this covers READS too -- see requiredPermission.
	"secrets": true,
	// The shape of the cluster.
	"namespaces":                      true,
	"nodes":                           true,
	"customresourcedefinitions":       true,
	"apiservices":                     true,
	"persistentvolumes":               true,
	"storageclasses":                  true,
	"csidrivers":                      true,
	"csinodes":                        true,
	"volumeattachments":               true,
	"priorityclasses":                 true,
	"runtimeclasses":                  true,
	"ingressclasses":                  true,
	"mutatingwebhookconfigurations":   true,
	"validatingwebhookconfigurations": true,
	"validatingadmissionpolicies":     true,
	"flowschemas":                     true,
	"prioritylevelconfigurations":     true,
	// Policy that bounds everything inside a namespace.
	"resourcequotas":  true,
	"limitranges":     true,
	"networkpolicies": true,
}

// reviewResources are the self-inspection APIs: POSTs that read, not writes.
//
// Headlamp issues these constantly -- it asks what it is allowed to do before
// deciding which buttons to render. Classifying them by HTTP method would make
// them writes and take the console away from every read-only user, which is the
// opposite of the point.
var reviewResources = map[string]bool{
	"selfsubjectaccessreviews": true,
	"selfsubjectrulesreviews":  true,
	"selfsubjectreviews":       true,
}

// requiredPermission returns the Provenance permission a proxied request needs.
//
// Fails toward the stricter answer. An unrecognised CLUSTER-SCOPED resource is
// treated as administration, because that is what changing the cluster's own
// furniture is; an unrecognised NAMESPACED one is treated as a workload, because
// that is what a custom resource in a namespace almost always is, and refusing
// those would make Operate useless on any cluster with CRDs -- which is most of
// them.
func requiredPermission(method, path string) string {
	resource, sub, namespaced := parseAPIPath(path)

	// Secrets are the exception to "reads need only read". The whole reason the
	// generated RBAC withholds Secrets is that a console able to read them is a
	// second secrets manager with different rules. That must not be reintroduced
	// by pointing a read-only console at a cluster-admin ServiceAccount.
	if resource == "secrets" {
		return permAdminister
	}
	if reviewResources[resource] {
		return permAccess
	}

	// Checked BEFORE the method, not after. `kubectl exec` opens with a **GET**
	// that upgrades the connection (SPDY) as well as with a POST, so a method
	// check reached first classified a shell as a read -- which handed every
	// read-only operator a root prompt in any container. A subresource that runs
	// code is never a read, whatever verb carries it.
	switch sub {
	case "exec", "attach", "portforward", "proxy", "eviction":
		return permOperate
	}

	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return permAccess
	}

	if administerResources[resource] {
		return permAdminister
	}
	if namespaced {
		return permOperate
	}
	// Cluster-scoped and unrecognised: administering something.
	return permAdminister
}

// parseAPIPath pulls the resource type, subresource and scope out of a
// Kubernetes API path.
//
// Shapes handled, which is all of them:
//
//	/api/v1/pods                                  cluster-wide list
//	/api/v1/namespaces                            the namespaces collection
//	/api/v1/namespaces/{ns}                       one namespace
//	/api/v1/namespaces/{ns}/pods/{name}/log       namespaced, with subresource
//	/apis/apps/v1/namespaces/{ns}/deployments/{n}/scale
//	/apis/apiextensions.k8s.io/v1/customresourcedefinitions/{name}
func parseAPIPath(path string) (resource, sub string, namespaced bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	// Drop the API prefix: "api/v1" (2) or "apis/{group}/{version}" (3).
	switch {
	case len(parts) >= 2 && parts[0] == "api":
		parts = parts[2:]
	case len(parts) >= 3 && parts[0] == "apis":
		parts = parts[3:]
	default:
		return "", "", false
	}
	if len(parts) == 0 {
		return "", "", false
	}

	// "namespaces" is both a resource and a path segment. It is the RESOURCE
	// when the path stops at it or at one name -- /namespaces, /namespaces/foo,
	// which is how a namespace is listed, created or deleted -- and a segment
	// when something follows: /namespaces/foo/pods.
	if parts[0] == "namespaces" {
		if len(parts) <= 2 {
			s := ""
			if len(parts) == 2 {
				s = "" // /namespaces/{name}: the name, not a subresource
			}
			return "namespaces", s, false
		}
		parts, namespaced = parts[2:], true
	}

	resource = parts[0]
	// parts is now resource[/name[/subresource]].
	if len(parts) >= 3 {
		sub = parts[2]
	}
	return resource, sub, namespaced
}

// authorize reports whether this principal may make this request, and the
// message to refuse it with.
//
// The message names the missing PROVENANCE permission rather than reporting a
// Kubernetes forbidden, because the cluster did not refuse this -- Provenance
// did, and an operator sent to argue with their cluster's RBAC will not find
// anything wrong with it.
func authorize(has func(string) bool, method, path string) (bool, string) {
	need := requiredPermission(method, path)
	if has(need) {
		return true, ""
	}
	switch need {
	case permOperate:
		return false, "changing workloads on a cluster needs the " + permOperate +
			" permission in Provenance; you have read access only"
	case permAdminister:
		return false, "this is a cluster-administration change (or a Secret), which " +
			"needs the " + permAdminister + " permission in Provenance"
	}
	return false, "reaching a cluster needs the " + permAccess + " permission in Provenance"
}
