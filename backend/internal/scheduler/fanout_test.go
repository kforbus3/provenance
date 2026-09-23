package scheduler

import "testing"

// OpenSSH's default MaxStartups is 10:30:100: from the 10th connection still
// mid-handshake, the jump host's sshd starts dropping new ones. Every scheduled
// scan dials through that one jump host, so a fan-out at or above 10 makes the
// scheduler itself the burst that gets scans dropped (a daily scan lost a host this
// way on 2026-09-23, at a fan-out of 16). Raising this needs MaxStartups raised on
// the jump host first -- change both together, or not at all.
const jumpHostMaxStartupsStart = 10

func TestScanFanoutStaysBelowJumpHostMaxStartups(t *testing.T) {
	if scanFanoutLimit >= jumpHostMaxStartupsStart {
		t.Fatalf("scanFanoutLimit %d reaches the jump host's MaxStartups start (%d); sshd will drop scans",
			scanFanoutLimit, jumpHostMaxStartupsStart)
	}
}
