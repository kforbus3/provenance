package store

import (
	"testing"
	"time"
)

func TestComposeHashIgnoresOnlyTrailingWhitespace(t *testing.T) {
	a := "services:\n  x:\n    image: a"
	if ComposeHash(a) != ComposeHash(a+"\n") || ComposeHash(a) != ComposeHash(a+"\n\n  \r\n") {
		t.Error("the final newline the deploy writes must not count as a change")
	}
	if ComposeHash(a) == ComposeHash(" "+a) || ComposeHash(a) == ComposeHash(a+"\n# note") {
		t.Error("anything but trailing whitespace is a change")
	}
}

// HostDiffers is only a claim when it can be one: deployed at this revision, read
// since that deploy, read successfully, and different.
func TestHostDiffersOnlyWhenTheReadingMeansIt(t *testing.T) {
	deployedAt := time.Now().Add(-time.Hour)
	after := deployedAt.Add(10 * time.Minute)
	before := deployedAt.Add(-10 * time.Minute)
	rev := 5
	base := func() ContainerStack {
		return ContainerStack{Compose: "services: {}", Revision: 5, Deployed: &rev, DeployState: "deployed",
			DeployedAt: &deployedAt, HostCheckedAt: &after, HostComposeSHA: ComposeHash("services: {x: 1}")}
	}

	st := base()
	if !hostDiffers(&st) {
		t.Fatal("a different file, read after the deploy, is a change on the host")
	}
	st = base()
	st.HostComposeSHA = ComposeHash(st.Compose + "\n")
	if hostDiffers(&st) {
		t.Error("the same file is not a change")
	}
	st = base()
	st.HostCheckedAt = &before
	if hostDiffers(&st) {
		t.Error("a reading from before the deploy says nothing about what it wrote")
	}
	st = base()
	newer := 6
	st.Revision = newer
	if hostDiffers(&st) {
		t.Error("a revision not yet deployed is expected to differ; drift already reports it as behind")
	}
	st = base()
	st.HostCheckError = "could not read"
	if hostDiffers(&st) {
		t.Error("a failed read is not evidence of a change")
	}
	st = base()
	st.HostCheckedAt = nil
	if hostDiffers(&st) {
		t.Error("never read is not a change")
	}
}
