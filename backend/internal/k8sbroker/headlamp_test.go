package k8sbroker

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kforbus3/provenance/backend/internal/store"
)

// The bug this exists for: "give Headlamp no token" was implemented as "give
// Headlamp no kubeconfig", so it knew about no clusters at all and the embedded
// console opened on "Something went wrong with cluster k3s-homelab".
func TestHeadlampIsToldWhichClustersExist(t *testing.T) {
	id := uuid.New()
	out := renderHeadlampConfig("https://prov.example.com/", []store.K8sCluster{
		{ID: id, Name: "k3s-homelab", Namespace: "default"},
	})
	if !strings.Contains(out, `name: "k3s-homelab"`) {
		t.Errorf("the cluster is not named, so Headlamp cannot find it:\n%s", out)
	}
	want := "https://prov.example.com/api/v1/k8s/clusters/" + id.String() + "/proxy"
	if !strings.Contains(out, want) {
		t.Errorf("server is not the broker URL:\n%s", out)
	}
	if !strings.Contains(out, `current-context: "k3s-homelab"`) {
		t.Error("without a current context Headlamp opens on nothing")
	}
}

// The other half of the same decision. A token here would be shared by every
// operator, so Provenance would record one actor for the whole team — which is
// the reason to embed a UI rather than link out to one.
func TestHeadlampIsGivenNoCredential(t *testing.T) {
	out := renderHeadlampConfig("https://p", []store.K8sCluster{
		{ID: uuid.New(), Name: "c1"},
	})
	// There IS a user entry — a context naming no user is invalid and client-go
	// silently drops it — but it must carry no credential.
	if !strings.Contains(out, "user: {}") {
		t.Errorf("expected a credential-free placeholder user:\n%s", out)
	}
	for _, forbidden := range []string{"token:", "client-key", "password", "flt_"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("a credential (%s) reached the shared Headlamp config", forbidden)
		}
	}
}

// A deployment with no clusters must still produce a valid document; an invalid
// one stops Headlamp starting at all, turning "nothing registered yet" into
// "the console is broken".
func TestNoClustersStillProducesAValidConfig(t *testing.T) {
	out := renderHeadlampConfig("https://p", nil)
	for _, want := range []string{"apiVersion: v1", "kind: Config", "clusters: []"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "current-context:") {
		t.Error("a current-context pointing at nothing is worse than none")
	}
}

func TestAHostileClusterNameIsQuoted(t *testing.T) {
	out := renderHeadlampConfig("https://p", []store.K8sCluster{
		{ID: uuid.New(), Name: `prod: "true"`},
	})
	if !strings.Contains(out, `\"true\"`) {
		t.Errorf("quotes in a cluster name were not escaped:\n%s", out)
	}
}
