package main

import (
	"reflect"
	"testing"
)

// What an upgrade may delete, and what it must not.
//
// This product is installed once and upgraded by bundle, so nothing prunes these
// images unless the installer does. A fleet upgraded since 0.70 was holding 152
// stack images across five components -- 49 tags of the backend alone, 9.2GB --
// and the first anyone knew of it was a disk-filling alert.
//
// The risk runs the other way too: this deletes images on a daemon it shares with
// the image builder and the PXE server on an imaging deployment, and removing the
// wrong one takes a running service with it.
func TestSupersededImages(t *testing.T) {
	const prefix = "provenance-"
	comps := []string{"backend", "frontend", "grype-scanner", "ansible-runner", "prov-updater"}

	tags := []string{
		// Superseded versions of our own components.
		"provenance-backend:1.0.0",
		"provenance-backend:1.1.0",
		"provenance-frontend:1.1.0",
		"provenance-ansible-runner:0.70.2",
		// The version just installed: running.
		"provenance-backend:1.2.1",
		"provenance-frontend:1.2.1",
		// The rollback anchor: the only route back if the new version is bad.
		"provenance-backend:rollback",
		"provenance-frontend:rollback",
		// Not ours. On an imaging deployment the daemon is shared with the image
		// builder and the PXE server, and an upgrade must not touch their images.
		"debian-ab-builder:rpm-amd64",
		"debian-ab-dnsmasq:latest",
		"provenance-builder-runner:latest",
		"postgres:16-alpine",
		"guacamole/guacd:1.5.5",
		// A component name that merely starts the same way is a different image.
		"provenance-backend-experiment:1.0.0",
		// Dangling layers and floating tags are not versions.
		"provenance-backend:<none>",
		"provenance-backend:latest",
		"<none>:<none>",
	}

	got := supersededImages(tags, prefix, "1.2.1", comps)
	want := []string{
		"provenance-ansible-runner:0.70.2",
		"provenance-backend:1.0.0",
		"provenance-backend:1.1.0",
		"provenance-frontend:1.1.0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("supersededImages:\n got %v\nwant %v", got, want)
	}
}

// Named individually, because each of these deleting something would break a
// running system rather than merely tidy one.
func TestSupersededImagesKeepsWhatMatters(t *testing.T) {
	const prefix = "provenance-"
	comps := []string{"backend", "prov-updater"}

	mustKeep := map[string]string{
		"provenance-backend:1.2.1":         "the version just installed is RUNNING",
		"provenance-backend:rollback":      "the rollback anchor is the only way back from a bad upgrade",
		"debian-ab-builder:rpm-amd64":      "not ours; the daemon is shared on an imaging deployment",
		"postgres:16-alpine":               "not ours, and the database",
		"provenance-backend:latest":        "a floating tag is not a superseded version",
		"provenance-backendish:1.0.0":      "a component whose name merely shares a prefix",
		"provenance-builder-runner:latest": "the image builder sidecar",
	}
	for ref, why := range mustKeep {
		got := supersededImages([]string{ref}, prefix, "1.2.1", comps)
		if len(got) != 0 {
			t.Errorf("would delete %s — %s", ref, why)
		}
	}

	// And the thing it exists to remove.
	got := supersededImages([]string{"provenance-backend:1.1.0"}, prefix, "1.2.1", comps)
	if len(got) != 1 {
		t.Errorf("did not offer to remove a superseded version: %v", got)
	}
}

// A component the bundle did not carry is not this upgrade's to prune.
func TestSupersededImagesOnlyCoversBundledComponents(t *testing.T) {
	got := supersededImages(
		[]string{"provenance-frontend:1.1.0", "provenance-backend:1.1.0"},
		"provenance-", "1.2.1", []string{"backend"})
	if len(got) != 1 || got[0] != "provenance-backend:1.1.0" {
		t.Errorf("got %v, want only the backend image", got)
	}
}
