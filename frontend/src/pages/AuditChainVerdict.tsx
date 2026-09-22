import { useState } from "react";
import {
  Alert, AlertTitle, Box, Button, Dialog, DialogActions, DialogContent,
  DialogContentText, DialogTitle, Link, Stack, TextField, Typography,
} from "@mui/material";
import { useMutation } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";
import {
  acknowledgeChainRange, scanAuditChain,
  type ChainScan, type VerifyResult,
} from "../api/audit";

// The verdict on the hash chain, and the two things an operator needs when it is bad.
//
// It used to be one line: intact, or broken at N. That line is honest about a healthy
// chain and misleading about every other kind. Acknowledging a break deliberately
// makes the verdict stop saying "broken" — otherwise a real break can never be seen
// behind an old one — so "Audit chain is intact." would have appeared over the 3,054
// rows the pre-0106 foreign key broke in the first production chain examined, with
// nothing on screen to say they were there.
//
// So: a chain with recorded exceptions gets its own verdict that counts them, a
// diagnosis that enumerates breaks instead of revealing them one acknowledgement at a
// time, and the bulk acknowledgement that diagnosis exists to inform.
export function AuditChainVerdict({
  result,
  onShowSequence,
}: {
  result: VerifyResult;
  // Naming a sequence and offering no way to see it is a strange place for an audit
  // tool to leave somebody, so every sequence this panel mentions is clickable.
  onShowSequence?: (seq: number) => void;
}) {
  const seqLink = (n: number) =>
    onShowSequence ? (
      <Link component="button" type="button" underline="hover"
        onClick={() => onShowSequence(n)}>{n}</Link>
    ) : (
      <>{n}</>
    );

  const has = useAuthStore((s) => s.has);
  const mayAcknowledge = has("System.Configure");
  const [scan, setScan] = useState<ChainScan | null>(null);
  const [ackOpen, setAckOpen] = useState(false);
  const [note, setNote] = useState("");

  const scanMut = useMutation<ChainScan>({
    mutationFn: scanAuditChain,
    onSuccess: setScan,
  });
  const ackMut = useMutation({
    mutationFn: () => acknowledgeChainRange(scan!.firstSeq, scan!.lastSeq, note),
    onSuccess: () => {
      setAckOpen(false);
      setNote("");
      scanMut.mutate();
    },
  });

  const ranges = result.acknowledgedRanges ?? [];
  const singles = result.acknowledgedBreaks ?? [];
  const excepted = ranges.reduce((n, g) => n + g.covered, 0) + singles.length;

  // Only the known signature can be acknowledged in bulk, so the button is offered
  // only when the scan found nothing else.
  const coverable =
    scan !== null &&
    scan.breakCount > 0 &&
    scan.unlinkedCount === 0 &&
    (scan.unexplainedCount ?? 0) === 0 &&
    scan.acknowledgedCount < scan.breakCount;

  return (
    <Box sx={{ mb: 2 }}>
      {!result.intact && (
        <Alert severity="error" sx={{ mb: 1 }}>
          <AlertTitle>Audit chain broken at sequence {seqLink(result.brokenAtSeq)}</AlertTitle>
          A row on or after this sequence has been altered, or removed. Nothing can make
          an altered row verify again — the next step is to establish what happened.
          <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
            <Button size="small" variant="outlined" disabled={scanMut.isPending}
              onClick={() => scanMut.mutate()}>
              {scanMut.isPending ? "Scanning…" : "Diagnose"}
            </Button>
          </Stack>
        </Alert>
      )}

      {result.intact && excepted === 0 && (
        <Alert severity="success" sx={{ mb: 1 }}>Audit chain is intact.</Alert>
      )}

      {result.intact && excepted > 0 && (
        // severity="info", not "warning". The state being described is "checked,
        // explained, and being watched" — an operator who has done the work should not
        // be shown the same colour as an operator who has an unexplained break. The
        // exceptions stay listed for ever, because a chain with unverifiable rows must
        // never present itself as whole; what changes is that this is no longer an
        // open question.
        <Alert severity="info" sx={{ mb: 1 }}>
          <AlertTitle>
            No tampering detected — with {excepted.toLocaleString()} recorded exception
            {excepted === 1 ? "" : "s"}
          </AlertTitle>
          Verification found nothing unaccounted for. Every row that cannot be verified
          has an investigated cause recorded against it, and checking continues past
          those rows — so a new alteration would still be caught. Those rows stay listed
          because they can never be verified again, not because anything is outstanding.
          {ranges.map((g) => (
            <Typography key={`${g.fromSeq}-${g.toSeq}`} variant="body2" sx={{ mt: 1 }}>
              <strong>Sequences {seqLink(g.fromSeq)}–{seqLink(g.toSeq)}</strong>{" "}
              ({g.covered.toLocaleString()} rows) — {g.by}, {formatDateTime(g.at)}: {g.note}
            </Typography>
          ))}
          {singles.map((b) => (
            <Typography key={b.brokenAtSeq} variant="body2" sx={{ mt: 1 }}>
              <strong>Sequence {seqLink(b.brokenAtSeq)}</strong> — {b.by}, {formatDateTime(b.at)}: {b.note}
            </Typography>
          ))}
        </Alert>
      )}

      {result.weakFromSeq ? (
        <Alert severity="info" sx={{ mb: 1 }}>
          <AlertTitle>
            {result.weakCount} row{result.weakCount === 1 ? "" : "s"} written without the
            chain key, from sequence {seqLink(result.weakFromSeq)}
          </AlertTitle>
          A row written while no <code>PROV_AUDIT_HMAC_KEY</code> was configured is hashed
          without it, so its integrity rests on plain SHA-256 rather than on the key.
          Anything appended in the same form would also verify — which is why this is
          reported rather than ignored. It is counted here, so a number that stays put is
          a fact about the past; a number that grows is happening now.
          <Typography variant="body2" sx={{ mt: 1 }}>
            The usual cause is a command-line tool run without the key in its environment.
            Provenance now refuses to append in that state, so this count should not
            increase. It cannot be cleared: the rows exist and rewriting them is the
            forgery this chain is built to detect.
          </Typography>
        </Alert>
      ) : null}

      {scanMut.isError && (
        <Alert severity="error" sx={{ mb: 1 }}>Could not scan the audit chain.</Alert>
      )}

      {scan && (
        <Alert severity="info" sx={{ mb: 1 }}>
          <AlertTitle>
            {scan.breakCount.toLocaleString()} of {scan.rows.toLocaleString()} rows do not verify
          </AlertTitle>
          <Typography variant="body2">
            {scan.breakCount > 0 && <>Sequences {seqLink(scan.firstSeq)}–{seqLink(scan.lastSeq)}. </>}
            {scan.noActorCount.toLocaleString()} have no actor, which is consistent with
            accounts having been deleted while the pre-0106 foreign key nulled that
            column — the rows lost a field rather than being edited, though a hash cannot
            tell the difference.
          </Typography>
          <Typography variant="body2" sx={{ mt: 1 }}>
            {scan.unlinkedCount === 0
              ? "No row has a broken link to its predecessor, so no row was removed, inserted or reordered."
              : `${scan.unlinkedCount.toLocaleString()} row(s) have a broken link to their predecessor: rows were removed, inserted or reordered. This cannot be acknowledged in bulk.`}
          </Typography>
          {(scan.unexplainedCount ?? 0) > 0 && (
            <Typography variant="body2" sx={{ mt: 1 }}>
              {scan.unexplainedCount!.toLocaleString()} break(s) still have an actor, so
              nothing here explains them. Investigate those individually.
            </Typography>
          )}
          {coverable && mayAcknowledge && (
            <Button size="small" variant="outlined" sx={{ mt: 1 }}
              onClick={() => setAckOpen(true)}>
              Acknowledge {scan.breakCount.toLocaleString()} rows…
            </Button>
          )}
        </Alert>
      )}

      <Dialog open={ackOpen} onClose={() => setAckOpen(false)} fullWidth maxWidth="sm">
        <DialogTitle>Acknowledge sequences {scan?.firstSeq}–{scan?.lastSeq}</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ mb: 2 }}>
            This repairs nothing. The {scan?.breakCount.toLocaleString()} rows stay exactly
            as they are and are reported for ever, with your note, including in compliance
            evidence packs — which will read “pass with exceptions”, never “intact”. What it
            changes is that verification continues past them, so a new alteration is
            visible again. It stops being honoured if any further row in this span ever
            fails to verify.
          </DialogContentText>
          <TextField
            label="What was investigated, and what was found" fullWidth multiline minRows={3}
            value={note} onChange={(e) => setNote(e.target.value)}
            helperText="Required. An acknowledgement with no account of what was found is indistinguishable from dismissing the alarm."
          />
          {ackMut.isError && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {(ackMut.error as { response?: { data?: { error?: string } } })?.response?.data?.error
                ?? "Could not record the acknowledgement."}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAckOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={!note.trim() || ackMut.isPending}
            onClick={() => ackMut.mutate()}>
            Record acknowledgement
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
