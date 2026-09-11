package reports

import (
	"bytes"
	"context"
	"fmt"
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
	intact, brokenAt, err := st.VerifyAuditChain(tenant.WithBypass(ctx))
	if err != nil {
		return nil, err
	}

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
	if intact {
		pdf.SetFillColor(232, 245, 233) // green tint
		pdf.SetTextColor(27, 94, 32)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 9, "PASS  -  the audit chain is cryptographically intact", "", 1, "L", true, 0, "")
	} else {
		pdf.SetFillColor(253, 236, 234) // red tint
		pdf.SetTextColor(150, 30, 20)
		pdf.SetFont("Helvetica", "B", 12)
		pdf.CellFormat(0, 9, fmt.Sprintf("FAIL  -  the audit chain is broken at sequence %d", brokenAt), "", 1, "L", true, 0, "")
	}
	pdf.Ln(1)
	if intact {
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
