package store

import (
	"testing"

	"github.com/google/uuid"
)

// Package lists survive in the column, a failed rescan does not erase them (the image
// did not change because a pull was rate limited), and an old scan without them is
// selected for rescanning.
func TestImagePackagesAreStoredAndSurviveAFailedRescan(t *testing.T) {
	s, _, ctx := scheduleTestStore(t)
	dg := "sha256:" + uuid.NewString()
	ref := ImageRef{Digest: dg, Image: "nginx@" + dg}

	if err := s.UpsertContainerImageScan(ctx, ContainerImageScan{Digest: dg, Image: ref.Image}); err != nil {
		t.Fatal(err)
	}
	stale, err := s.StaleContainerImages(ctx, []ImageRef{ref}, "", 1<<40)
	if err != nil || len(stale) != 1 {
		t.Fatalf("a scan without packages must be rescanned once: stale=%v err=%v", stale, err)
	}

	want := pkgs("nginx", "1.31.6-r0", "libssl3", "3.5.8-r0")
	if err := s.UpsertContainerImageScan(ctx, ContainerImageScan{Digest: dg, Image: ref.Image, Packages: want}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertContainerImageScan(ctx, ContainerImageScan{Digest: dg, Image: ref.Image, Error: "toomanyrequests"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ContainerImageScanDetails(ctx, []string{dg})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[dg].Packages) != 2 || got[dg].Packages[1].Name != "libssl3" {
		t.Fatalf("packages after a failed rescan = %+v", got[dg].Packages)
	}
	if _, err := s.RebuildImageRefs(ctx); err != nil {
		t.Fatalf("RebuildImageRefs: %v", err)
	}
}
