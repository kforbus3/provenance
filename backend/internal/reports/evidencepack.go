package reports

import (
	"bytes"
	"context"
	"fmt"
	"github.com/kforbus3/provenance/backend/internal/hosttrust"
	"strconv"
	"time"

	"github.com/go-pdf/fpdf"

	"github.com/kforbus3/provenance/backend/internal/store"
	"github.com/kforbus3/provenance/backend/internal/tenant"
)

// packMeta carries the non-data inputs for an evidence pack.
type packMeta struct {
	AppName     string
	GeneratedBy string
	From, To    time.Time
	Now         time.Time
}

// buildEvidencePack renders a single-file PDF compliance evidence pack for the
// window [From, To): a cover page, a tamper-evidence attestation derived from the
// hash-chained audit log, and summary statistics for privileged access, certificate
// issuance, scan posture, vulnerabilities, and privileged-command activity. It is
// the human-readable, archivable companion to the per-domain CSV exports (which
// carry the full line-item detail). Data is gathered by reusing the CSV export
// queries and summarized in memory, so the pack can never disagree with the CSVs.
func buildEvidencePack(ctx context.Context, st *store.Store, m packMeta) ([]byte, error) {
	// Counts, not rows. See store.EvidenceSummaryFor: the pack prints fourteen
	// scalars, and it used to obtain them by materialising every session,
	// certificate, scan, finding and audit event in the window -- with the audit
	// detail JSON untruncated -- and measuring the slices in Go.
	sum, err := st.EvidenceSummaryFor(ctx, m.From, m.To)
	if err != nil {
		return nil, err
	}

	// The integrity attestation covers the ENTIRE chain (integrity is a global
	// property — a broken link anywhere is a problem), not just the window. Verify
	// under bypass so it sees every event: the hash chain is a single global
	// sequence, and a tenant-scoped read would hide other tenants' rows and falsely
	// report the chain broken.
	chain, err := st.VerifyAuditChainDetail(tenant.WithBypass(ctx))
	if err != nil {
		return nil, err
	}
	intact := chain.BrokenAtSeq == 0
	brokenAt := chain.BrokenAtSeq
	// Acknowledged breaks are rows that DO NOT verify. They have an investigated cause
	// recorded against them, which is why the verdict is no longer "broken" — but the
	// rows are still altered or missing, and a pack that printed a plain PASS over them
	// would be the one misleading document in a compliance file.
	//
	// The case is not hypothetical: the foreign key dropped in migration 0106 nulled
	// actor_id on every event of any deleted user, and the first production chain
	// examined afterwards had 3,054 such rows out of 5,521. Acknowledging them is
	// correct and necessary — otherwise a real break can never be seen behind them —
	// and reporting the result as "cryptographically intact" would not be.
	excepted := 0
	for _, g := range chain.AcknowledgedRanges {
		excepted += g.Covered
	}
	excepted += len(chain.Acknowledged)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.SetAutoPageBreak(true, 20)
	pdf.AddPage()

	// The 14 standard PDF core fonts encode text as Windows-1252, not UTF-8, so any
	// non-ASCII byte (an em-dash, or an accented white-label app name / username)
	// would otherwise render as mojibake. Translate every string through fpdf's
	// UTF-8 -> CP1252 converter before it is drawn.
	tr := pdf.UnicodeTranslatorFromDescriptor("")

	// --- layout helpers ---
	title := func(s string) {
		pdf.SetFont("Helvetica", "B", 22)
		pdf.SetTextColor(25, 30, 40)
		pdf.CellFormat(0, 12, tr(s), "", 1, "L", false, 0, "")
	}
	subtle := func(s string) {
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(120, 120, 120)
		pdf.CellFormat(0, 6, tr(s), "", 1, "L", false, 0, "")
	}
	h2 := func(s string) {
		pdf.Ln(4)
		pdf.SetFont("Helvetica", "B", 14)
		pdf.SetTextColor(25, 30, 40)
		pdf.CellFormat(0, 9, tr(s), "B", 1, "L", false, 0, "")
		pdf.Ln(1)
	}
	kv := func(k, v string) {
		pdf.SetFont("Helvetica", "", 11)
		pdf.SetTextColor(110, 110, 110)
		pdf.CellFormat(70, 7, tr(k), "", 0, "L", false, 0, "")
		pdf.SetFont("Helvetica", "B", 11)
		pdf.SetTextColor(25, 30, 40)
		pdf.CellFormat(0, 7, tr(v), "", 1, "L", false, 0, "")
	}
	note := func(s string) {
		pdf.SetFont("Helvetica", "I", 9)
		pdf.SetTextColor(130, 130, 130)
		pdf.MultiCell(0, 5, tr(s), "", "L", false)
	}

	// --- cover ---
	title(m.AppName + " — Compliance Evidence Pack")
	subtle(fmt.Sprintf("Reporting period: %s to %s (UTC)",
		m.From.Format("2006-01-02"), m.To.Format("2006-01-02")))
	subtle(fmt.Sprintf("Generated: %s by %s", m.Now.Format("2006-01-02 15:04 MST"), m.GeneratedBy))
	pdf.Ln(2)

	// --- audit integrity attestation (the differentiator) ---
	h2("Audit-Log Integrity Attestation")
	headline, tone := chainAttestation(intact, excepted, brokenAt)
	pdf.SetFillColor(tone.fillR, tone.fillG, tone.fillB)
	pdf.SetTextColor(tone.textR, tone.textG, tone.textB)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.CellFormat(0, 9, headline, "", 1, "L", true, 0, "")
	pdf.Ln(1)
	if intact && excepted > 0 {
		note("Every recorded event hashes forward from its predecessor as H(previous_hash || event). " +
			"A full genesis-to-latest verification found no UNEXPLAINED alteration: every row that " +
			"does not verify has an investigated cause recorded against it, and verification " +
			"continues past those rows, so a new alteration would still be detected. The affected " +
			"rows are listed below and are not repaired - nothing can make an altered row verify " +
			"again. Each exception should be read before this pack is relied upon as evidence.")
		pdf.Ln(1)
		for _, g := range chain.AcknowledgedRanges {
			note(fmt.Sprintf("Sequences %d-%d: %d row(s), recorded by %s on %s. %s",
				g.FromSeq, g.ToSeq, g.Covered, g.By, g.At.Format("2006-01-02"), g.Note))
		}
		for _, b := range chain.Acknowledged {
			note(fmt.Sprintf("Sequence %d: recorded by %s on %s. %s",
				b.BrokenAtSeq, b.By, b.At.Format("2006-01-02"), b.Note))
		}
	} else if intact {
		note("Every recorded event hashes forward from its predecessor as H(previous_hash || event). " +
			"A full genesis-to-latest verification found no altered or missing rows, so the access, " +
			"certificate, scan, and command records summarized below are demonstrably tamper-evident.")
	} else {
		note("A full genesis-to-latest verification found the chain broken at the sequence above. " +
			"Events on or after that point may have been altered or removed and must be investigated " +
			"before this pack is relied upon as evidence.")
	}

	// --- privileged access ---
	h2("Privileged Access (SSH sessions)")
	kv("Sessions in period", strconv.Itoa(sum.Sessions))
	kv("Distinct users", strconv.Itoa(sum.SessionUsers))
	kv("Distinct hosts reached", strconv.Itoa(sum.SessionHosts))

	// --- how hosts are actually reached ---
	//
	// A pack that reports only session counts implies every session was equally well
	// protected. They are not: a host reached with a standing vaulted credential on
	// its management address gives up the per-session certificate AND the tunnel, and
	// until this section existed nothing in the evidence said which hosts those were.
	// The posture is derived from each host record, so it cannot describe a
	// configuration the fleet has since moved off.
	h2("Host Access Paths")
	if hosts, herr := st.ListHosts(tenant.WithBypass(ctx), 100000, 0); herr == nil && len(hosts) > 0 {
		counts := map[hosttrust.Tier]int{}
		for _, h := range hosts {
			if h.AccessPosture != nil {
				counts[h.AccessPosture.Tier]++
			}
		}
		for _, t := range hosttrust.All() {
			kv(tierLabel(t), fmt.Sprintf("%d host(s)", counts[t]))
		}
		if weak := counts[hosttrust.TierVaultedDirect] + counts[hosttrust.TierVaultedOverlay]; weak > 0 {
			note(fmt.Sprintf("%d host(s) authenticate with a standing credential held in the "+
				"vault rather than a certificate minted for each session. Ending one person's "+
				"access to those hosts means rotating that credential, not revoking a "+
				"certificate serial.", weak))
		}
		if direct := counts[hosttrust.TierBrokeredDirect] + counts[hosttrust.TierVaultedDirect]; direct > 0 {
			note(fmt.Sprintf("%d host(s) are reachable on their management address rather than "+
				"only through the overlay, so strict overlay mode cannot confine connections "+
				"to them.", direct))
		}
	} else {
		note("No hosts are enrolled, or the inventory could not be read.")
	}

	// --- certificate issuance ---
	h2("Certificate Issuance (ephemeral SSH credentials)")
	kv("Certificates issued", strconv.Itoa(sum.CertsIssued))
	kv("Of which revoked", strconv.Itoa(sum.CertsRevoked))

	// --- scan posture ---
	h2("Security Scan Posture")
	kv("Scans run", strconv.Itoa(sum.Scans))
	kv("Completed", strconv.Itoa(sum.ScansCompleted))
	kv("Rules passed / failed", fmt.Sprintf("%d / %d", sum.RulesPassed, sum.RulesFailed))

	// --- vulnerabilities ---
	h2("Vulnerabilities (CVE findings)")
	kv("Total findings", strconv.Itoa(sum.VulnFindings))
	kv("Critical", strconv.Itoa(sum.VulnCritical))
	kv("High", strconv.Itoa(sum.VulnHigh))

	// --- privileged command activity ---
	h2("Privileged-Command Activity")
	kv("Audited events in period", strconv.Itoa(sum.AuditEvents))
	kv("Commands flagged by policy", strconv.Itoa(sum.CommandsFlagged))
	kv("Commands blocked by policy", strconv.Itoa(sum.CommandsBlocked))

	pdf.Ln(6)
	note("This pack is a summary. Full line-item detail for each section is available as a CSV export " +
		"(Access, Audit trail, Certificate issuance, Scan posture, Vulnerabilities) over the same period. " +
		"The integrity attestation above is re-verifiable at any time via the audit-log verification endpoint.")

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// --- summary helpers over ReportTable rows (string cells) ---

// attestationTone is the colour of the attestation banner.
type attestationTone struct {
	fillR, fillG, fillB int
	textR, textG, textB int
}

// chainAttestation is the one sentence a compliance reader will quote, so it is a
// function of its own with a test rather than three branches inside a page of PDF
// drawing calls.
//
// The middle case is the one that matters. A chain can have rows that do not verify
// AND no unexplained alteration: each failing row has an investigated cause recorded
// against it, which is what lets verification continue past them so a new alteration
// is still visible. Reporting that as "cryptographically intact" would be false, and
// reporting it as FAIL would make every pack from a deployment that ever deleted a
// user unusable. It gets its own verdict, with the count in it.
func chainAttestation(intact bool, excepted int, brokenAt int64) (string, attestationTone) {
	green := attestationTone{232, 245, 233, 27, 94, 32}
	amber := attestationTone{255, 243, 224, 120, 70, 10}
	red := attestationTone{253, 236, 234, 150, 30, 20}
	switch {
	case intact && excepted > 0:
		return fmt.Sprintf("PASS WITH EXCEPTIONS  -  %d row(s) do not verify, with a recorded cause",
			excepted), amber
	case intact:
		return "PASS  -  the audit chain is cryptographically intact", green
	default:
		return fmt.Sprintf("FAIL  -  the audit chain is broken at sequence %d", brokenAt), red
	}
}

// tierLabel renders an access tier for a compliance reader, who should not have to
// know the product's internal vocabulary to read its evidence.
func tierLabel(t hosttrust.Tier) string {
	switch t {
	case hosttrust.TierBrokeredOverlay:
		return "Per-session certificate, overlay only"
	case hosttrust.TierBrokeredDirect:
		return "Per-session certificate, management address"
	case hosttrust.TierVaultedOverlay:
		return "Standing vaulted credential, overlay only"
	case hosttrust.TierVaultedDirect:
		return "Standing vaulted credential, management address"
	}
	return string(t)
}
