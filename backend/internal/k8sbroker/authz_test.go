package k8sbroker

import (
	"net/http"
	"testing"
)

// The classification IS the security boundary, so it is tested as a table of
// real Kubernetes API paths rather than through the handler.
//
// Every row is a path Headlamp or kubectl actually issues. A wrong answer here
// either takes the console away from someone entitled to it or hands a
// read-only operator the cluster.
func TestRequiredPermission(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		// Reads are reads.
		{http.MethodGet, "/api/v1/pods", permAccess},
		{http.MethodGet, "/api/v1/namespaces/default/pods", permAccess},
		{http.MethodGet, "/api/v1/namespaces/default/pods/web-1/log", permAccess},
		{http.MethodGet, "/api/v1/nodes", permAccess},
		{http.MethodGet, "/apis/apps/v1/namespaces/default/deployments", permAccess},
		{http.MethodGet, "/version", permAccess},

		// Workload changes need Operate.
		{http.MethodPatch, "/apis/apps/v1/namespaces/default/deployments/web/scale", permOperate},
		{http.MethodDelete, "/api/v1/namespaces/default/pods/web-1", permOperate},
		{http.MethodPost, "/apis/batch/v1/namespaces/default/jobs", permOperate},
		{http.MethodPut, "/api/v1/namespaces/default/configmaps/app", permOperate},
		{http.MethodPost, "/apis/networking.k8s.io/v1/namespaces/default/ingresses", permOperate},

		// Administering the cluster needs Administer.
		{http.MethodPost, "/api/v1/namespaces", permAdminister},
		{http.MethodDelete, "/api/v1/namespaces/staging", permAdminister},
		{http.MethodPost, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", permAdminister},
		{http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", permAdminister},
		{http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/namespaces/default/rolebindings", permAdminister},
		{http.MethodPost, "/api/v1/namespaces/default/serviceaccounts", permAdminister},
		{http.MethodPost, "/api/v1/persistentvolumes", permAdminister},
		{http.MethodPost, "/apis/storage.k8s.io/v1/storageclasses", permAdminister},
		{http.MethodPatch, "/api/v1/nodes/k3s", permAdminister},
		{http.MethodPost, "/api/v1/namespaces/default/resourcequotas", permAdminister},
		{http.MethodPost, "/apis/networking.k8s.io/v1/namespaces/default/networkpolicies", permAdminister},

		// Secrets are Administer even to READ. A console that can read Secrets is
		// a second secrets manager with different rules, which is the thing the
		// generated cluster RBAC withholds them to prevent -- and pointing a
		// read-only console at a cluster-admin ServiceAccount must not
		// reintroduce it.
		{http.MethodGet, "/api/v1/namespaces/default/secrets", permAdminister},
		{http.MethodGet, "/api/v1/namespaces/default/secrets/db-password", permAdminister},
		{http.MethodPost, "/api/v1/namespaces/default/secrets", permAdminister},

		// The self-inspection APIs are POSTs that read. Headlamp issues them
		// before rendering anything, so classifying them by method would take the
		// console away from every read-only user.
		{http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", permAccess},
		{http.MethodPost, "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", permAccess},
		{http.MethodPost, "/apis/authentication.k8s.io/v1/selfsubjectreviews", permAccess},

		// A shell in a container is not a read, whatever its verb.
		{http.MethodGet, "/api/v1/namespaces/default/pods/web-1/exec", permOperate},
		{http.MethodPost, "/api/v1/namespaces/default/pods/web-1/exec", permOperate},
		{http.MethodGet, "/api/v1/namespaces/default/pods/web-1/portforward", permOperate},
		{http.MethodPost, "/api/v1/namespaces/default/pods/web-1/attach", permOperate},

		// An unknown NAMESPACED resource is a custom resource, which is ordinary
		// workload territory -- refusing these would make Operate useless on any
		// cluster running cert-manager or similar.
		{http.MethodPost, "/apis/cert-manager.io/v1/namespaces/default/certificates", permOperate},
		// An unknown CLUSTER-SCOPED one is the cluster's own furniture.
		{http.MethodPost, "/apis/cert-manager.io/v1/clusterissuers", permAdminister},
	}
	for _, c := range cases {
		if got := requiredPermission(c.method, c.path); got != c.want {
			t.Errorf("%s %s = %s, want %s", c.method, c.path, got, c.want)
		}
	}
}

// A read-only operator must keep a working console, and must not be able to
// change anything through it.
func TestAReadOnlyOperatorCanBrowseButNotChange(t *testing.T) {
	has := func(p string) bool { return p == permAccess }

	for _, path := range []string{
		"/api/v1/namespaces/default/pods",
		"/apis/apps/v1/namespaces/default/deployments",
		"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", // POST, but a read
	} {
		method := http.MethodGet
		if path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" {
			method = http.MethodPost
		}
		if ok, why := authorize(has, method, path); !ok {
			t.Errorf("read-only user refused %s %s: %s", method, path, why)
		}
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodDelete, "/api/v1/namespaces/default/pods/web-1"},
		{http.MethodPatch, "/apis/apps/v1/namespaces/default/deployments/web/scale"},
		{http.MethodPost, "/api/v1/namespaces"},
		{http.MethodGet, "/api/v1/namespaces/default/secrets/db"},
		{http.MethodPost, "/api/v1/namespaces/default/pods/web-1/exec"},
	} {
		ok, why := authorize(has, c.method, c.path)
		if ok {
			t.Errorf("read-only user allowed %s %s", c.method, c.path)
		}
		// The refusal has to name the Provenance permission: the cluster did not
		// refuse this, so an operator sent to look at cluster RBAC finds nothing.
		if !ok && why == "" {
			t.Errorf("%s %s refused with no explanation", c.method, c.path)
		}
	}
}

// An operator may run workloads and must not be able to administer the cluster
// or read Secrets -- including on a cluster whose ServiceAccount is
// cluster-admin, which is the arrangement this exists for.
func TestAnOperatorCannotAdministerTheCluster(t *testing.T) {
	has := func(p string) bool { return p == permAccess || p == permOperate }

	for _, c := range []struct{ method, path string }{
		{http.MethodDelete, "/api/v1/namespaces/default/pods/web-1"},
		{http.MethodPost, "/apis/batch/v1/namespaces/default/jobs"},
		{http.MethodPost, "/api/v1/namespaces/default/pods/web-1/exec"},
	} {
		if ok, why := authorize(has, c.method, c.path); !ok {
			t.Errorf("operator refused %s %s: %s", c.method, c.path, why)
		}
	}
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/namespaces"},
		{http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"},
		{http.MethodPost, "/api/v1/namespaces/default/serviceaccounts"},
		{http.MethodGet, "/api/v1/namespaces/default/secrets/db"},
		{http.MethodPatch, "/api/v1/nodes/k3s"},
	} {
		if ok, _ := authorize(has, c.method, c.path); ok {
			t.Errorf("operator allowed %s %s — that is administering the cluster",
				c.method, c.path)
		}
	}
}

func TestAnAdministratorIsAllowedEverything(t *testing.T) {
	has := func(string) bool { return true }
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/namespaces"},
		{http.MethodGet, "/api/v1/namespaces/default/secrets/db"},
		{http.MethodPost, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions"},
		{http.MethodDelete, "/api/v1/nodes/k3s"},
	} {
		if ok, why := authorize(has, c.method, c.path); !ok {
			t.Errorf("administrator refused %s %s: %s", c.method, c.path, why)
		}
	}
}

func TestParseAPIPathScope(t *testing.T) {
	cases := []struct {
		path       string
		resource   string
		sub        string
		namespaced bool
	}{
		{"/api/v1/namespaces", "namespaces", "", false},
		{"/api/v1/namespaces/staging", "namespaces", "", false},
		{"/api/v1/namespaces/default/pods", "pods", "", true},
		{"/api/v1/namespaces/default/pods/web-1", "pods", "", true},
		{"/api/v1/namespaces/default/pods/web-1/log", "pods", "log", true},
		{"/api/v1/nodes/k3s", "nodes", "", false},
		{"/apis/apps/v1/namespaces/d/deployments/web/scale", "deployments", "scale", true},
		{"/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "customresourcedefinitions", "", false},
		{"/healthz", "", "", false},
	}
	for _, c := range cases {
		res, sub, ns := parseAPIPath(c.path)
		if res != c.resource || sub != c.sub || ns != c.namespaced {
			t.Errorf("parseAPIPath(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.path, res, sub, ns, c.resource, c.sub, c.namespaced)
		}
	}
}
