package monitor

import (
	"testing"

	"github.com/kforbus3/provenance/backend/internal/models"
)

// Which hosts get a liveness check that does not log in.
//
// keith asked why his access point logged "admin logged in from 10.10.0.208" every
// 30 seconds when nobody was touching it. It was Provenance's monitor: the probe
// authenticates, discovers the device is not a Linux host, collects nothing, and
// hangs up — two log lines per device per sweep, ~5,700 a day each, all shipped
// to the log collector where they buried real events.
//
// A Linux host must NOT take this path: there the login is the whole point, since
// the probe runs the fact, metric and container collectors over it.
func TestOnlyDevicesWeCollectNothingFromSkipTheLogin(t *testing.T) {
	routeros := &models.Host{Options: models.HostOptions{DeviceType: "routeros"}}
	legacy := &models.Host{Options: models.HostOptions{RouterOSAPI: true}}
	linux := &models.Host{}

	if !probesWithoutLogin(routeros) {
		t.Error("a RouterOS device still logs in, so the device keeps logging Provenance twice a minute")
	}
	if !probesWithoutLogin(legacy) {
		t.Error("a host marked by the legacy routerOsApi flag still logs in")
	}
	if probesWithoutLogin(linux) {
		t.Error("a Linux host skipped the login — the probe would collect no facts, " +
			"no metrics and no containers, and report the host online on a banner read")
	}
}
