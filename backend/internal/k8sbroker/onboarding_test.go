package k8sbroker

import (
	"strings"
	"testing"
)

// The whole value of generating this is that a rushed operator does not reach
// for cluster-admin because it is one line and works.
//
// `administer` is excluded from this deliberately and tested separately: it
// grants cluster-admin by design, and the point of this test is that the two
// levels somebody picks for SAFETY cannot drift into granting it. If a level is
// ever added here, add it to this loop.
func TestTheManifestNeverGrantsClusterAdminOrSecrets(t *testing.T) {
	for _, level := range []string{"read", "operate"} {
		m := onboardingManifest(level, "")
		if strings.Contains(m, "cluster-admin") {
			t.Errorf("%s manifest grants cluster-admin", level)
		}
		if strings.Contains(m, `"secrets"`) {
			t.Errorf("%s manifest grants Secrets", level)
		}
		if strings.Contains(m, "name: edit") {
			t.Errorf("%s manifest binds the built-in edit role, which grants Secrets", level)
		}
		if strings.Contains(m, `"serviceaccounts"`) {
			t.Errorf("%s manifest grants serviceaccounts — a route to a token", level)
		}
	}
}

// Read must be genuinely read: a "read" level that can delete is worse than no
// level at all, because it is chosen by people who wanted safety.
func TestReadGrantsNoWrites(t *testing.T) {
	m := onboardingManifest("read", "")
	for _, verb := range []string{`"create"`, `"update"`, `"patch"`, `"delete"`} {
		if strings.Contains(m, verb) {
			t.Errorf("the read manifest contains the verb %s", verb)
		}
	}
	if strings.Contains(m, "provenance-operate") {
		t.Error("the read manifest includes the operate role")
	}
}

func TestOperateGrantsWorkloadLifecycleAndLogs(t *testing.T) {
	m := onboardingManifest("operate", "")
	for _, want := range []string{"provenance-operate", `"deployments"`, `"pods/log"`, `"delete"`} {
		if !strings.Contains(m, want) {
			t.Errorf("the operate manifest is missing %s", want)
		}
	}
}

// "view" does not cover cluster-scoped nodes, and every cluster UI lists them.
// Discovered the hard way: nodes returned 403 while everything else worked.
func TestEveryLevelCanReadNodes(t *testing.T) {
	for _, level := range []string{"read", "operate"} {
		if !strings.Contains(onboardingManifest(level, ""), "provenance-node-reader") {
			t.Errorf("%s manifest cannot read nodes; the built-in view role does not cover them", level)
		}
	}
}

// Confining writes is the only thing that bounds the mount-a-Secret route, so
// the namespace choice has to actually change the binding kind.
func TestANamespaceConfinesWritesToARoleBinding(t *testing.T) {
	scoped := onboardingManifest("operate", "apps")
	if !strings.Contains(scoped, "kind: RoleBinding") || !strings.Contains(scoped, "namespace: apps") {
		t.Errorf("a namespace should produce a RoleBinding in it:\n%s", scoped)
	}
	wide := onboardingManifest("operate", "")
	if strings.Contains(wide, "kind: RoleBinding") {
		t.Error("with no namespace the operate binding should be cluster-wide")
	}
	// Reading stays cluster-wide either way, or the UI cannot list namespaces.
	if !strings.Contains(scoped, "name: provenance-view") {
		t.Error("read access must stay cluster-wide even when writes are confined")
	}
}

// kubectl create token is time-bounded, which is wrong for a credential nothing
// rotates — the manifest has to produce a durable one.
func TestTheTokenSecretIsDurable(t *testing.T) {
	m := onboardingManifest("read", "")
	if !strings.Contains(m, "type: kubernetes.io/service-account-token") {
		t.Error("no long-lived token Secret; kubectl create token expires in an hour")
	}
}

// `administer` grants the cluster, and says so.
//
// The argument for offering it at all is that withholding it did not make the
// console safer, it made it incomplete -- and an operator who cannot create a
// namespace from the console goes back to a terminal, where nothing is audited.
// Who may USE it is decided by Provenance permissions on every request (see
// authz.go), which is what makes a fully capable ServiceAccount defensible.
func TestAdministerGrantsTheCluster(t *testing.T) {
	m := onboardingManifest("administer", "")
	if !strings.Contains(m, "cluster-admin") {
		t.Error("the administer manifest does not grant cluster-admin, so namespaces, " +
			"CRDs and Helm still will not work")
	}
	if !strings.Contains(m, "provenance-administer") {
		t.Error("the administer binding is not named for what it is")
	}
	// It has to be obvious in the file itself what was chosen: this is applied
	// with kubectl by somebody who should be able to read what they are granting.
	if !strings.Contains(m, "Access level: administer") {
		t.Error("the manifest does not state its access level")
	}
	for _, want := range []string{"Secrets", "cluster-admin"} {
		if !strings.Contains(m, want) {
			t.Errorf("the manifest does not mention %q, so what it grants is not "+
				"visible to whoever applies it", want)
		}
	}
}

// Adding a third level must not have changed the first two.
func TestAdministerDidNotChangeReadOrOperate(t *testing.T) {
	for _, level := range []string{"read", "operate"} {
		m := onboardingManifest(level, "")
		if strings.Contains(m, "provenance-administer") || strings.Contains(m, "cluster-admin") {
			t.Errorf("the %s manifest gained cluster administration", level)
		}
	}
}

// A namespace bounds workload writes. It cannot bound cluster administration,
// because what `administer` grants is cluster-scoped -- so accepting the
// combination would hand back a manifest granting almost none of what was
// asked for, discovered one missing button at a time.
func TestAdministerIgnoresNoNamespaceSilently(t *testing.T) {
	// The handler refuses the combination; the renderer must not quietly produce
	// a namespaced administer binding if it is ever called directly.
	m := onboardingManifest("administer", "staging")
	if strings.Contains(m, "kind: RoleBinding\nmetadata:\n  name: provenance-administer") {
		t.Error("administer was rendered as a namespaced RoleBinding, which would grant " +
			"almost nothing of what it claims")
	}
}
