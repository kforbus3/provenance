import { useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Grid, Stack, TextField, Typography,
} from "@mui/material";
import DownloadIcon from "@mui/icons-material/Download";
import { useMutation } from "@tanstack/react-query";
import { downloadReport, downloadEvidencePack, type ReportKind } from "../api/reports";
import DescriptionIcon from "@mui/icons-material/Description";

const REPORTS: Array<{ kind: ReportKind; title: string; desc: string }> = [
  { kind: "access", title: "Access report", desc: "Every SSH session — who connected to which host, from where, when it started and ended, and how it closed." },
  { kind: "audit", title: "Audit trail", desc: "All audit events: logins, session terminations, host/user/role/config changes, with full detail." },
  { kind: "certificates", title: "Certificate issuance", desc: "SSH certificates the CA issued — serial, principal, subject, validity window, and revocation." },
  { kind: "scans", title: "Scan posture", desc: "Security-scan results over time — profile, score, and pass/fail counts per host." },
  { kind: "vulnerabilities", title: "Vulnerabilities", desc: "Every CVE finding from vulnerability scans — host, package, installed vs. fixed version, severity, and CVSS score." },
];

function isoDaysAgo(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().slice(0, 10);
}

// ReportsPage exports org-wide compliance evidence as CSV over a date range.
// Gated by Audit.View.
export function ReportsPage() {
  const [from, setFrom] = useState(isoDaysAgo(30));
  const [to, setTo] = useState(isoDaysAgo(0));
  const [pending, setPending] = useState<ReportKind | null>(null);

  const dl = useMutation({
    mutationFn: (kind: ReportKind) => downloadReport(kind, from, to),
    onMutate: (kind) => setPending(kind),
    onSettled: () => setPending(null),
  });
  const pack = useMutation({ mutationFn: () => downloadEvidencePack(from, to) });

  return (
    <Box sx={{ maxWidth: 900 }}>
      <Typography variant="h5">Reports</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Download org-wide compliance evidence as CSV for the selected date range — for SOC 2 / ISO /
        PCI audits and access reviews.
      </Typography>

      <Card variant="outlined" sx={{ mb: 2 }}>
        <CardContent>
          <Stack direction="row" spacing={2} flexWrap="wrap">
            <TextField
              type="date" size="small" label="From" value={from}
              onChange={(e) => setFrom(e.target.value)}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              type="date" size="small" label="To" value={to}
              onChange={(e) => setTo(e.target.value)} InputLabelProps={{ shrink: true }}
            />
          </Stack>
        </CardContent>
      </Card>

      {(dl.isError || pack.isError) && <Alert severity="error" sx={{ mb: 2 }}>Could not build the report.</Alert>}

      <Card variant="outlined" sx={{ mb: 2, borderColor: "primary.main" }}>
        <CardContent>
          <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }} justifyContent="space-between">
            <Box sx={{ minWidth: 0 }}>
              <Stack direction="row" spacing={1} alignItems="center">
                <DescriptionIcon color="primary" fontSize="small" />
                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Compliance evidence pack (PDF)</Typography>
              </Stack>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                One auditor-ready PDF for the selected period: a tamper-evidence attestation of the
                hash-chained audit log, plus summary statistics for access, certificates, scan posture,
                vulnerabilities, and privileged-command activity. Line-item detail stays in the CSVs below.
              </Typography>
            </Box>
            <Button
              variant="contained" startIcon={<DescriptionIcon />} sx={{ flexShrink: 0 }}
              disabled={pack.isPending} onClick={() => pack.mutate()}
            >
              {pack.isPending ? "Preparing…" : "Download PDF"}
            </Button>
          </Stack>
        </CardContent>
      </Card>

      <Grid container spacing={2}>
        {REPORTS.map((r) => (
          <Grid item xs={12} sm={6} key={r.kind}>
            <Card variant="outlined" sx={{ height: "100%" }}>
              <CardContent>
                <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>{r.title}</Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5, minHeight: 60 }}>
                  {r.desc}
                </Typography>
                <Button
                  variant="contained" size="small" startIcon={<DownloadIcon />}
                  disabled={pending !== null} onClick={() => dl.mutate(r.kind)}
                >
                  {pending === r.kind ? "Preparing…" : "Download CSV"}
                </Button>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
}
