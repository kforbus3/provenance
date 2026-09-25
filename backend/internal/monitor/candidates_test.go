package monitor

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/kforbus3/provenance/backend/internal/models"
)

func resolverSaying(err error, calls *int) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) {
		*calls++
		if err != nil {
			return nil, err
		}
		return []string{"10.0.2.9"}, nil
	}
}

var nxdomain = &net.DNSError{Err: "no such host", Name: "wap", IsNotFound: true}

// The access point: a working IP address, and a bare hostname the jump host cannot
// resolve. The name is left out, and DNS is not asked again every sweep.
func TestAnUnresolvableHostnameIsNotRaced(t *testing.T) {
	calls := 0
	m := &Monitor{}
	m.unresolvable.lookup = resolverSaying(nxdomain, &calls)
	h := &models.Host{Hostname: "wap", Address: "10.0.2.220"}

	for i := 0; i < 3; i++ {
		if got := m.probeCandidates(context.Background(), h); !reflect.DeepEqual(got, []string{"10.0.2.220"}) {
			t.Fatalf("sweep %d raced %v", i+1, got)
		}
	}
	if calls != 1 {
		t.Fatalf("asked DNS %d times in three sweeps; want once", calls)
	}
}

// A name that resolves stays: 16 hosts reach their LAN fallback this way.
func TestAResolvableHostnameIsStillAFallback(t *testing.T) {
	calls := 0
	m := &Monitor{}
	m.unresolvable.lookup = resolverSaying(nil, &calls)
	h := &models.Host{Hostname: "gitlab", WGAddress: "10.100.0.12"}
	if got := m.probeCandidates(context.Background(), h); !reflect.DeepEqual(got, []string{"10.100.0.12", "gitlab"}) {
		t.Fatalf("got %v", got)
	}
}

// A DNS failure that is not "no such name" -- a timeout -- says nothing about the
// name, and must not remove a way to reach the host.
func TestADNSTimeoutDoesNotDropTheHostname(t *testing.T) {
	calls := 0
	m := &Monitor{}
	m.unresolvable.lookup = resolverSaying(&net.DNSError{Err: "i/o timeout", Name: "gitlab", IsTimeout: true}, &calls)
	h := &models.Host{Hostname: "gitlab", WGAddress: "10.100.0.12"}
	if got := m.probeCandidates(context.Background(), h); len(got) != 2 {
		t.Fatalf("a timeout dropped a candidate: %v", got)
	}
	m.unresolvable.lookup = resolverSaying(errors.New("server misbehaving"), &calls)
	if got := m.probeCandidates(context.Background(), h); len(got) != 2 {
		t.Fatalf("a server failure dropped a candidate: %v", got)
	}
}

// A hostname that is the only address is kept, so an unreachable host says why.
func TestAHostnameThatIsTheOnlyAddressIsKept(t *testing.T) {
	calls := 0
	m := &Monitor{}
	m.unresolvable.lookup = resolverSaying(nxdomain, &calls)
	h := &models.Host{Hostname: "wap"}
	if got := m.probeCandidates(context.Background(), h); !reflect.DeepEqual(got, []string{"wap"}) {
		t.Fatalf("got %v", got)
	}
	if calls != 0 {
		t.Fatal("no lookup is needed when there is nothing else to try")
	}
}

// A name added to DNS is picked up once the negative answer expires.
func TestAnUnresolvableNameIsRetriedLater(t *testing.T) {
	calls := 0
	u := &unresolvableNames{lookup: resolverSaying(nxdomain, &calls)}
	now := time.Now()
	if !u.notFound(context.Background(), "wap", now) {
		t.Fatal("expected not found")
	}
	u.lookup = resolverSaying(nil, &calls)
	if !u.notFound(context.Background(), "wap", now.Add(time.Minute)) {
		t.Fatal("within the TTL the cached answer stands")
	}
	if u.notFound(context.Background(), "wap", now.Add(unresolvableTTL+time.Second)) {
		t.Fatal("after the TTL the name is asked again, and now resolves")
	}
}
