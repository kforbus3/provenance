package k8sbroker

import (
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/httpx"
)

// onboarding emits the RBAC a cluster needs before Provenance can broker it.
//
// Joining a cluster otherwise means hand-writing a ServiceAccount, a role, a
// binding and a non-expiring token Secret from documentation — the first thing a
// new user hits, and the step where a rushed operator reaches for
// cluster-admin because it is one line and works.
//
// Three levels, because there is no single right answer and pretending
// otherwise is how the wrong one gets picked:
//
//	read       — browse and diagnose. Cannot change anything, cannot read Secrets.
//	operate    — the above plus workload lifecycle. Still no Secrets, no
//	             ServiceAccounts, no RBAC, no namespaces.
//	administer — the cluster, administered. Namespaces, CRDs, RBAC, storage,
//	             network policy, quotas, Secrets. This is cluster-admin.
//
// `read` and `operate` are unchanged, so a cluster already joined at either
// gains nothing by this existing. `administer` is a deliberate, named choice.
//
// Why offer it at all, having argued against cluster-admin here: because the
// alternative was worse. Withholding it did not make the console safer, it made
// it incomplete -- a console that cannot create a namespace, install a chart or
// define a CRD is not somewhere a cluster is administered, and an operator who
// needs those goes back to a terminal, which is the outcome embedding a console
// was meant to prevent. Withheld capability does not disappear; it relocates to
// somewhere with no audit trail.
//
// The original objection stands and is answered by HOW it is offered: the danger
// was never that cluster-admin exists, it was a rushed operator reaching for it
// as the default because it is one line and works. Here it is the third of three
// named options, it is not the default, the manifest says what it grants, and
// Provenance reports what each cluster actually permits (see capabilities) so
// nobody has to infer their own access from a missing button.
//
// `administer` binds the built-in cluster-admin rather than enumerating an
// equivalent role. An enumerated one would be a snapshot: it would miss every
// API group added by a later Kubernetes release and every CRD installed after it
// was written, failing silently and looking like a broken UI. If the intent is
// "this cluster is administered from here", say that, do not approximate it.
func (h *handler) onboarding(w http.ResponseWriter, r *http.Request) {
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("access")))
	if level == "" {
		level = "read"
	}
	if level != "read" && level != "operate" && level != "administer" {
		httpx.WriteError(w, http.StatusBadRequest,
			"access must be read, operate or administer")
		return
	}
	// A namespace bounds workload writes. It cannot bound cluster administration:
	// namespaces, CRDs, storage classes and nodes are cluster-scoped, so a
	// namespaced binding would silently grant almost none of what was asked for
	// and the operator would discover it one missing button at a time.
	if level == "administer" && strings.TrimSpace(r.URL.Query().Get("namespace")) != "" {
		httpx.WriteError(w, http.StatusBadRequest,
			"administer cannot be confined to a namespace — what it grants is "+
				"cluster-scoped. Use operate with a namespace to bound writes.")
		return
	}
	ns := strings.TrimSpace(r.URL.Query().Get("namespace")) // empty = cluster-wide
	h.audit(r, "k8s.onboarding_manifest", uuid.Nil, map[string]any{
		"access": level, "namespace": ns,
	})
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(onboardingManifest(level, ns)))
}

// onboardingManifest renders the YAML. Pure, so what it grants is testable.
func onboardingManifest(level, namespace string) string {
	var b strings.Builder
	b.WriteString("# Apply this on the cluster you are joining, then paste the token and CA\n")
	b.WriteString("# it produces into Provenance:\n")
	b.WriteString("#\n")
	b.WriteString("#   kubectl apply -f provenance-rbac.yaml\n")
	b.WriteString("#   kubectl -n kube-system get secret provenance-token -o jsonpath='{.data.token}' | base64 -d\n")
	b.WriteString("#   kubectl -n kube-system get secret provenance-token -o jsonpath='{.data.ca\\.crt}' | base64 -d\n")
	b.WriteString("#\n")
	b.WriteString("# Access level: " + level + "\n")
	if namespace != "" {
		b.WriteString("# Writes are confined to namespace: " + namespace + "\n")
	}
	b.WriteString("---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n")
	b.WriteString("  name: provenance\n  namespace: kube-system\n")

	// Reading is always cluster-wide: a UI that cannot list namespaces or nodes
	// is not useful, and "view" excludes Secrets.
	b.WriteString("---\n# Cluster-wide READ. The built-in \"view\" role excludes Secrets.\n")
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n")
	b.WriteString("  name: provenance-view\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n")
	b.WriteString("  kind: ClusterRole\n  name: view\nsubjects:\n")
	b.WriteString("  - kind: ServiceAccount\n    name: provenance\n    namespace: kube-system\n")

	// "view" does not cover cluster-scoped nodes, and a cluster UI lists them.
	b.WriteString("---\n# \"view\" does NOT cover cluster-scoped nodes, which every cluster UI lists.\n")
	b.WriteString("# One narrow role beats widening the binding above for a single resource.\n")
	b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n")
	b.WriteString("  name: provenance-node-reader\nrules:\n  - apiGroups: [\"\"]\n")
	b.WriteString("    resources: [\"nodes\"]\n    verbs: [\"get\", \"list\", \"watch\"]\n")
	b.WriteString("---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n")
	b.WriteString("  name: provenance-node-reader\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n")
	b.WriteString("  kind: ClusterRole\n  name: provenance-node-reader\nsubjects:\n")
	b.WriteString("  - kind: ServiceAccount\n    name: provenance\n    namespace: kube-system\n")

	if level == "operate" {
		b.WriteString("---\n# Workload lifecycle. Deliberately NOT the built-in \"edit\", which grants\n")
		b.WriteString("# Secrets read AND write. ServiceAccounts are excluded too: being able to\n")
		b.WriteString("# create one is a route to a token, and a token is a route back to\n")
		b.WriteString("# everything this role withholds.\n")
		b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n")
		b.WriteString("  name: provenance-operate\nrules:\n")
		b.WriteString("  - apiGroups: [\"apps\"]\n    resources: [\"deployments\", \"statefulsets\", \"daemonsets\", \"replicasets\",\n")
		b.WriteString("                \"deployments/scale\", \"statefulsets/scale\", \"replicasets/scale\"]\n")
		b.WriteString("    verbs: [\"get\", \"list\", \"watch\", \"create\", \"update\", \"patch\", \"delete\"]\n")
		b.WriteString("  - apiGroups: [\"batch\"]\n    resources: [\"jobs\", \"cronjobs\"]\n")
		b.WriteString("    verbs: [\"get\", \"list\", \"watch\", \"create\", \"update\", \"patch\", \"delete\"]\n")
		b.WriteString("  - apiGroups: [\"\"]\n    resources: [\"pods\", \"services\", \"configmaps\", \"persistentvolumeclaims\"]\n")
		b.WriteString("    verbs: [\"get\", \"list\", \"watch\", \"create\", \"update\", \"patch\", \"delete\"]\n")
		b.WriteString("  - apiGroups: [\"\"]\n    resources: [\"pods/log\", \"events\"]\n    verbs: [\"get\", \"list\", \"watch\"]\n")
		b.WriteString("  - apiGroups: [\"networking.k8s.io\"]\n    resources: [\"ingresses\"]\n")
		b.WriteString("    verbs: [\"get\", \"list\", \"watch\", \"create\", \"update\", \"patch\", \"delete\"]\n")
		if namespace != "" {
			b.WriteString("---\n# Bound in ONE namespace. Anything able to create workloads in a namespace\n")
			b.WriteString("# can mount that namespace's Secrets into a pod and read them -- no RBAC\n")
			b.WriteString("# rule prevents that -- so confining writes is what bounds it.\n")
			b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\nmetadata:\n")
			b.WriteString("  name: provenance-operate\n  namespace: " + namespace + "\n")
		} else {
			b.WriteString("---\n# Cluster-wide writes. Note: anything able to create workloads in a\n")
			b.WriteString("# namespace can mount that namespace's Secrets into a pod and read them.\n")
			b.WriteString("# No RBAC rule prevents that; confining writes to one namespace does.\n")
			b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n")
			b.WriteString("  name: provenance-operate\n")
		}
		b.WriteString("roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: ClusterRole\n")
		b.WriteString("  name: provenance-operate\nsubjects:\n")
		b.WriteString("  - kind: ServiceAccount\n    name: provenance\n    namespace: kube-system\n")
	}

	if level == "administer" {
		b.WriteString("---\n# THE CLUSTER, ADMINISTERED. This is cluster-admin: namespaces, CRDs,\n")
		b.WriteString("# RBAC, storage, network policy, quotas -- and Secrets, read and write.\n")
		b.WriteString("#\n")
		b.WriteString("# Bound to the built-in role rather than an enumerated copy on purpose: a\n")
		b.WriteString("# copy is a snapshot that misses every API group a later Kubernetes adds\n")
		b.WriteString("# and every CRD installed after it was written, and it fails by looking\n")
		b.WriteString("# like a broken UI rather than by saying no.\n")
		b.WriteString("#\n")
		b.WriteString("# Provenance still brokers every call and still records it against the\n")
		b.WriteString("# person who made it. What this removes is the cluster's own refusal, not\n")
		b.WriteString("# Provenance's accounting. Choose it for a cluster you administer from\n")
		b.WriteString("# here; choose operate for one where you only run workloads.\n")
		b.WriteString("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\nmetadata:\n")
		b.WriteString("  name: provenance-administer\nroleRef:\n  apiGroup: rbac.authorization.k8s.io\n")
		b.WriteString("  kind: ClusterRole\n  name: cluster-admin\nsubjects:\n")
		b.WriteString("  - kind: ServiceAccount\n    name: provenance\n    namespace: kube-system\n")
	}

	b.WriteString("---\n# A non-expiring token. `kubectl create token` is time-bounded (1h by\n")
	b.WriteString("# default), which is wrong for a registered credential nothing rotates.\n")
	b.WriteString("apiVersion: v1\nkind: Secret\nmetadata:\n  name: provenance-token\n")
	b.WriteString("  namespace: kube-system\n  annotations:\n")
	b.WriteString("    kubernetes.io/service-account.name: provenance\n")
	b.WriteString("type: kubernetes.io/service-account-token\n")
	return b.String()
}
