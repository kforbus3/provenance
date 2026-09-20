package store

import "testing"

// The python:3.14 case: the registry's current index digest is the image's SECOND
// RepoDigest, so equality against the first reports a current host as behind.
func TestRunningDigestMatchesAnyOfTheImagesDigests(t *testing.T) {
	const (
		older   = "sha256:a2e9788143507cacbb754fcc06ad3b7108ca9c334f97a466906103846107cdd5"
		current = "sha256:be8ccd085666c34273c9dc5607c9842f8b2e3116128aae45148ce164c07ce09d"
	)
	img := TrackedImage{Repository: "python", Tag: "3.14", Digest: older,
		Digests: []string{older, current}}

	if !img.RunningDigest(current) {
		t.Error("the host runs an image that answers to the registry's current digest " +
			"and was reported as behind — this is the update that could never be applied")
	}
	if !img.RunningDigest(older) {
		t.Error("the older index digest names the same image and must also match")
	}
	if img.RunningDigest("sha256:unrelated") {
		t.Error("an unrelated digest matched")
	}
	if img.RunningDigest("") {
		t.Error("an empty registry digest matched, which would silence every check")
	}

	// A row collected before the set existed still answers on its single digest.
	old := TrackedImage{Digest: older}
	if !old.RunningDigest(older) {
		t.Error("a pre-upgrade row lost the comparison it used to make")
	}
	if old.RunningDigest(current) {
		t.Error("a pre-upgrade row matched a digest it never recorded")
	}
}
