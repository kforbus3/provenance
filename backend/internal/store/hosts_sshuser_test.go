package store

import "testing"

// SetHostSSHUser only ever fills a blank — "an operator who typed a user meant
// it". A migration that has just replaced the account ON the host needs the
// opposite, and reusing the fill-a-blank one silently did nothing: it matched no
// rows, Exec reported no error, and three production hosts went offline with a
// working SSH server and a valid certificate, their rows still naming the account
// that had just been deleted.
//
// This pins the two apart at the level the mistake was made: their names and
// documented contracts. The SQL itself is exercised by store-queries against a
// real server.
func TestTheFillAndTheChangeAreDifferentFunctions(t *testing.T) {
	// Both must exist. If someone collapses them back into one, this stops
	// compiling — which is the point.
	var (
		fill   = (*Store).SetHostSSHUser
		change = (*Store).ChangeHostSSHUser
	)
	if fill == nil || change == nil {
		t.Fatal("both a fill-if-empty and a deliberate-change setter must exist")
	}
}
