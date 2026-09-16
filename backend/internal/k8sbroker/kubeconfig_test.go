package k8sbroker

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/store"
)

func TestTheKubeconfigPointsAtTheBrokerNotTheCluster(t *testing.T) {
	id := uuid.New()
	out := renderKubeconfig("https://prov.example.com", "keith", "flt_tok", []store.K8sCluster{
		{ID: id, Name: "k3s-homelab", APIServer: "https://k3s.internal:6443", Namespace: "default"},
	})
	want := "https://prov.example.com/api/v1/k8s/clusters/" + id.String() + "/proxy"
	if !strings.Contains(out, want) {
		t.Errorf("server is not the broker URL:\n%s", out)
	}
	// The whole point is that the operator never reaches the cluster directly,
	// and never holds its credential.
	if strings.Contains(out, "k3s.internal") {
		t.Error("the cluster's real API server leaked into the kubeconfig")
	}
	if !strings.Contains(out, "namespace: \"default\"") {
		t.Error("the cluster's default namespace should seed the context")
	}
}

func TestEveryClusterGetsAContext(t *testing.T) {
	out := renderKubeconfig("https://p", "u", "t", []store.K8sCluster{
		{ID: uuid.New(), Name: "alpha"}, {ID: uuid.New(), Name: "beta"},
	})
	for _, n := range []string{"alpha", "beta"} {
		if strings.Count(out, `"`+n+`"`) < 2 { // once as a cluster, once as a context
			t.Errorf("cluster %q is missing a cluster or context entry:\n%s", n, out)
		}
	}
	if !strings.Contains(out, `current-context: "alpha"`) {
		t.Error("current-context should be set, or kubectl needs --context on every call")
	}
}

// A cluster name is operator-supplied text. Unquoted, a name containing a colon
// or a quote produces a file that either fails to parse or parses as something
// else — and the operator's only clue is kubectl complaining about YAML.
func TestAHostileClusterNameCannotBreakTheDocument(t *testing.T) {
	for _, name := range []string{`prod: true`, `say "hi"`, "back\\slash", "tab\there"} {
		out := renderKubeconfig("https://p", "u", "t", []store.K8sCluster{
			{ID: uuid.New(), Name: name},
		})
		for _, line := range strings.Split(out, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), "- name:") {
				continue
			}
			v := strings.TrimSpace(strings.SplitN(line, "- name:", 2)[1])
			if !strings.HasPrefix(v, `"`) || !strings.HasSuffix(v, `"`) {
				t.Errorf("name %q rendered unquoted as %s", name, v)
			}
			if strings.Count(v, `"`)%2 != 0 {
				t.Errorf("name %q left unbalanced quotes: %s", name, v)
			}
		}
	}
}

func TestTheScopeAndLifetimeAreDeliberate(t *testing.T) {
	// A kubeconfig that could reach the rest of the API would make the file
	// equivalent to its owner's account.
	if kubeconfigScope != "/api/v1/k8s" {
		t.Errorf("scope = %q; a kubeconfig token must reach only the Kubernetes broker", kubeconfigScope)
	}
	// A credential in a file that never expires is one nobody revokes, because
	// nobody remembers it exists.
	if kubeconfigTTL == 0 {
		t.Error("kubeconfig tokens must expire")
	}
}
