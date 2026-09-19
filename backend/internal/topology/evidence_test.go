package topology

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kforbus3/provenance/backend/internal/models"
	"github.com/kforbus3/provenance/backend/internal/store"
)

var checked = time.Now()

func host(name, addr string, inv *models.HostInventory) models.Host {
	return models.Host{ID: uuid.New(), Hostname: name, Address: addr, Inventory: inv}
}

func inv(virt string, mounts []models.NetworkMount, ports ...models.ListeningPort) *models.HostInventory {
	return &models.HostInventory{
		Virtualisation: virt, NetworkMounts: mounts, MountsCheckedAt: &checked, ListeningPorts: ports,
	}
}

func mount(server, source, target, fs string) models.NetworkMount {
	return models.NetworkMount{Server: server, Source: source, Target: target, FSType: fs}
}

// The whole point: an edge somebody typed in is corroborated by what the host itself
// reports, and one nobody typed in is offered rather than assumed.
func TestStorageIsConfirmedOrSuggested(t *testing.T) {
	nas := host("nas", "10.10.0.9", inv("", nil))
	// hypervisor mounts nas by ADDRESS, while the edge names the host: the index has to
	// bridge that or the evidence is missed and a recorded edge looks unverifiable.
	hypervisor := host("hypervisor", "10.10.0.10", inv("", []models.NetworkMount{
		mount("10.10.0.9", "10.10.0.9:/tank/vm", "/mnt/vm", "nfs4"),
	}))
	other := host("coder", "10.10.0.11", inv("", []models.NetworkMount{
		mount("nas", "nas:/tank/home", "/home", "nfs4"),
	}))
	hosts := []models.Host{nas, hypervisor, other}

	// Recorded: hypervisor -> nas (storage). Observed too, so it is a confirmation.
	rec := []store.HostDependencyEdge{{HostID: hypervisor.ID, DependsOnID: nas.ID, Kind: KindStorage}}
	v := ForHost(hypervisor.ID, hosts, rec)
	if len(v.Confirmations) != 1 || v.Confirmations[0].DependsOnID != nas.ID {
		t.Fatalf("hypervisor -> nas was not confirmed: %+v", v)
	}
	if !strings.Contains(v.Confirmations[0].Evidence, "/mnt/vm") {
		t.Errorf("confirmation does not say what was seen: %q", v.Confirmations[0].Evidence)
	}
	if len(v.Suggestions) != 0 {
		t.Errorf("a recorded edge was also suggested: %+v", v.Suggestions)
	}

	// coder mounts nas and nobody recorded it: a suggestion, never a silent write.
	v = ForHost(other.ID, hosts, nil)
	if len(v.Suggestions) != 1 || v.Suggestions[0].DependsOnID != nas.ID || v.Suggestions[0].Kind != KindStorage {
		t.Fatalf("coder -> nas was not suggested: %+v", v)
	}
	if len(v.Confirmations) != 0 {
		t.Errorf("an unrecorded edge was reported as confirmed: %+v", v)
	}
}

// A NAS that Provenance does not manage cannot be recorded as an edge at all. That is
// not a suggestion and must not be silently dropped either -- it is the one blind
// spot no amount of data entry closes.
func TestUnmanagedServerIsReportedSeparately(t *testing.T) {
	h := host("media", "10.10.0.30", inv("", []models.NetworkMount{
		mount("synology", "synology:/volume1/tv", "/mnt/tv", "nfs4"),
	}))
	v := ForHost(h.ID, []models.Host{h}, nil)
	if len(v.Unmanaged) != 1 || v.Unmanaged[0].Server != "synology" {
		t.Fatalf("unmanaged server not reported: %+v", v)
	}
	if len(v.Suggestions) != 0 {
		t.Errorf("suggested an edge to a host that does not exist: %+v", v.Suggestions)
	}
}

// Many mounts from one server are ONE dependency. Three suggestions for the same
// edge is a panel nobody reads, and the schema would reject the duplicates anyway.
func TestManyMountsFromOneServerAreOneSuggestion(t *testing.T) {
	nas := host("nas", "10.10.0.9", inv("", nil))
	h := host("docker", "10.10.0.12", inv("", []models.NetworkMount{
		mount("nas", "nas:/a", "/mnt/a", "nfs4"),
		mount("nas", "nas:/b", "/mnt/b", "nfs4"),
		mount("nas", "nas:/c", "/mnt/c", "nfs4"),
		mount("nas", "nas:/d", "/mnt/d", "nfs4"),
	}))
	v := ForHost(h.ID, []models.Host{nas, h}, nil)
	if len(v.Suggestions) != 1 {
		t.Fatalf("got %d suggestions for one server: %+v", len(v.Suggestions), v.Suggestions)
	}
	// Bounded, and honest about what it left out.
	if !strings.Contains(v.Suggestions[0].Evidence, "and 1 more") {
		t.Errorf("evidence does not bound the list: %q", v.Suggestions[0].Evidence)
	}
}

// A guest cannot see its hypervisor. With one in the fleet the answer is forced; with
// two it is a coin toss that would be recorded as a fact and read back as one by
// something deciding what to reboot.
func TestHypervisorIsSuggestedOnlyWhenUnambiguous(t *testing.T) {
	web := models.ListeningPort{Port: 8006, Exposed: true}
	hypervisor := host("hypervisor", "10.10.0.10", inv("", nil, web))
	guest := host("k3s", "10.10.0.105", inv("kvm", nil))
	v := ForHost(guest.ID, []models.Host{hypervisor, guest}, nil)
	if len(v.Suggestions) != 1 || v.Suggestions[0].Kind != KindHypervisor || v.Suggestions[0].DependsOnID != hypervisor.ID {
		t.Fatalf("sole hypervisor was not suggested: %+v", v.Suggestions)
	}
	if !strings.Contains(v.Suggestions[0].Evidence, "kvm") || !strings.Contains(v.Suggestions[0].Evidence, "only") {
		t.Errorf("evidence does not explain the guess: %q", v.Suggestions[0].Evidence)
	}

	// Second hypervisor: say nothing at all.
	vhost2 := host("vhost2", "10.10.0.13", inv("", nil, web))
	v = ForHost(guest.ID, []models.Host{hypervisor, vhost2, guest}, nil)
	for _, s := range v.Suggestions {
		if s.Kind == KindHypervisor {
			t.Fatalf("guessed a hypervisor out of two candidates: %+v", s)
		}
	}

	// A bare-metal host is not a guest of anything.
	metal := host("nas", "10.10.0.9", inv("", nil))
	v = ForHost(metal.ID, []models.Host{hypervisor, metal}, nil)
	if len(v.Suggestions) != 0 {
		t.Errorf("bare metal was given a hypervisor: %+v", v.Suggestions)
	}
}

// A host loopback-mounting its own export is not a dependency, and the schema forbids
// the self-edge that would be suggested.
func TestAHostMountingItselfIsNotADependency(t *testing.T) {
	nas := host("nas", "10.10.0.9", inv("", []models.NetworkMount{
		mount("10.10.0.9", "10.10.0.9:/tank/x", "/mnt/x", "nfs4"),
	}))
	v := ForHost(nas.ID, []models.Host{nas}, nil)
	if len(v.Suggestions) != 0 || len(v.Unmanaged) != 0 {
		t.Fatalf("self-mount produced %+v / %+v", v.Suggestions, v.Unmanaged)
	}
}

// "Nothing to corroborate with" must not render as "corroborated nothing". A host
// swept before this existed has no mount report, and a UI that showed its edges as
// unverified would be making a claim from missing data.
func TestCollectedSaysWhetherTheHostHasEverReported(t *testing.T) {
	never := models.Host{ID: uuid.New(), Hostname: "old", Inventory: &models.HostInventory{}}
	if ForHost(never.ID, []models.Host{never}, nil).Collected {
		t.Error("a host that has never reported its mounts was marked collected")
	}
	h := host("new", "10.10.0.20", inv("", []models.NetworkMount{}))
	if !ForHost(h.ID, []models.Host{h}, nil).Collected {
		t.Error("a host that reported no mounts was marked not collected")
	}
}
