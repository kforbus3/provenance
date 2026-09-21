package reports

import (
	"strings"
	"testing"
)

// The evidence pack is the document that goes in a compliance file, so the one thing
// it must never do is describe an audit log as intact when rows in it do not verify.
//
// The path to that was short. Acknowledging a break makes the verdict stop saying
// "broken" — deliberately, because otherwise a genuine break can never be seen behind
// an old one — and the pack asked only for that boolean. So the moment somebody
// acknowledged the 3,054 rows the pre-0106 foreign key had broken, the pack would have
// started printing "the audit chain is cryptographically intact" over them.
func TestEvidencePackNeverCallsAChainWithExceptionsIntact(t *testing.T) {
	headline, _ := chainAttestation(true, 3054, 0)
	if strings.Contains(headline, "cryptographically intact") {
		t.Errorf("the attestation reads %q with 3,054 rows that do not verify — a compliance "+
			"pack would be asserting integrity over known-altered rows", headline)
	}
	if !strings.Contains(headline, "3054") {
		t.Errorf("the attestation %q does not say how many rows are excepted; the reader "+
			"cannot weigh an exception whose size is not stated", headline)
	}
	if !strings.Contains(headline, "EXCEPTIONS") {
		t.Errorf("the attestation %q does not mark itself as qualified", headline)
	}
}

// And the two unambiguous cases still read unambiguously.
func TestEvidencePackAttestationForACleanAndABrokenChain(t *testing.T) {
	clean, greenTone := chainAttestation(true, 0, 0)
	if !strings.HasPrefix(clean, "PASS  -") || !strings.Contains(clean, "intact") {
		t.Errorf("a chain with nothing wrong reads %q", clean)
	}
	broken, redTone := chainAttestation(false, 0, 214)
	if !strings.HasPrefix(broken, "FAIL") || !strings.Contains(broken, "214") {
		t.Errorf("a broken chain reads %q; it must name the sequence", broken)
	}
	if greenTone == redTone {
		t.Error("pass and fail are drawn in the same colour")
	}
	// An unacknowledged break outranks any number of exceptions: something unexplained
	// is the finding, and a qualified pass would bury it.
	stillBroken, _ := chainAttestation(false, 3054, 214)
	if !strings.HasPrefix(stillBroken, "FAIL") {
		t.Errorf("a chain with BOTH exceptions and an unexplained break reads %q; the "+
			"unexplained break has to lead", stillBroken)
	}
}
