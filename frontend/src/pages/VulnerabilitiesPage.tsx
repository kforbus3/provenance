import { useRef, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, MenuItem, Paper, Stack, Table, TableBody,
  TableCell, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import SecurityIcon from "@mui/icons-material/Security";
import RefreshIcon from "@mui/icons-material/Refresh";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";
import { listHosts } from "../api/hosts";
import { listGroups } from "../api/admin";
import {
  triggerVulnScan, latestVulnScans, listVulnScans, getVulnScan, clearFailedVulnScans,
  vulnDbStatus, vulnDbUpdate, vulnDbImport, type VulnFinding,
} from "../api/vulnscan";

const SEV_COLOR: Record<string, "error" | "warning" | "info" | "default"> = {
  Critical: "error", High: "error", Medium: "warning", Low: "info", Negligible: "default", Unknown: "default",
};

function cvssColor(score: number): "error" | "warning" | "info" | "default" {
  if (score >= 9) return "error";
  if (score >= 7) return "error";
  if (score >= 4) return "warning";
  if (score > 0) return "info";
  return "default";
}

// VulnerabilitiesPage: run CVE vulnerability scans and view per-host findings with
// CVSS scores, plus a fleet roll-up. Gated by Host.Scan; DB management by
// System.Configure.
export function VulnerabilitiesPage() {
  const qc = useQueryClient();
  const canConfig = useAuthStore((s) => s.has("System.Configure"));
  const [scanOpen, setScanOpen] = useState(false);
  const [findingsScan, setFindingsScan] = useState<string | null>(null);

  const { data: rollup = [] } = useQuery({ queryKey: ["vuln-latest"], queryFn: latestVulnScans });
  const { data: recent = [] } = useQuery({
    queryKey: ["vuln-recent"], queryFn: () => listVulnScans(),
    refetchInterval: 5000, // surface running scans as they progress
  });
  const running = recent.filter((s) => s.status === "pending" || s.status === "running");
  const failed = recent.filter((s) => s.status === "failed").slice(0, 5);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["vuln-latest"] });
    void qc.invalidateQueries({ queryKey: ["vuln-recent"] });
  };
  const clearFailed = useMutation({
    mutationFn: clearFailedVulnScans,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["vuln-recent"] }),
  });

  return (
    <Box sx={{ maxWidth: 1150 }}>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h5">Vulnerabilities</Typography>
          <Typography variant="body2" color="text.secondary">
            Linux hosts: match installed packages against a CVE database (Grype), scored by CVSS.
            Windows hosts: the CVEs remediated by missing security updates, from Microsoft's update metadata.
          </Typography>
        </Box>
        <Tooltip title="Refresh"><Button startIcon={<RefreshIcon />} onClick={refresh} sx={{ mr: 1 }}>Refresh</Button></Tooltip>
        <Button variant="contained" startIcon={<SecurityIcon />} onClick={() => setScanOpen(true)}>Scan hosts</Button>
      </Stack>

      <DbStatusCard canConfig={canConfig} />

      {running.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {running.length} scan{running.length > 1 ? "s" : ""} in progress…
        </Alert>
      )}
      {failed.length > 0 && (
        <Alert
          severity="warning"
          sx={{ mb: 2 }}
          action={
            <Button color="inherit" size="small" disabled={clearFailed.isPending} onClick={() => clearFailed.mutate()}>
              Clear
            </Button>
          }
        >
          Recent failures: {failed.map((f) => `${f.hostname} (${f.error || "error"})`).join("; ")}
        </Alert>
      )}

      <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>Fleet roll-up (latest scan per host)</Typography>
      <Paper variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Host</TableCell>
              <TableCell align="right">Max CVSS</TableCell>
              <TableCell align="right">Critical</TableCell>
              <TableCell align="right">High</TableCell>
              <TableCell align="right">Medium</TableCell>
              <TableCell align="right">Total</TableCell>
              <TableCell>Scanned</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rollup.map((s) => (
              <TableRow key={s.id} hover sx={{ cursor: "pointer" }} onClick={() => setFindingsScan(s.id)}>
                <TableCell>{s.hostname}</TableCell>
                <TableCell align="right">
                  <Chip size="small" color={cvssColor(s.maxCvss)} label={s.maxCvss.toFixed(1)} />
                </TableCell>
                <TableCell align="right">{s.critical > 0 ? <Chip size="small" color="error" label={s.critical} /> : "—"}</TableCell>
                <TableCell align="right">{s.high > 0 ? <Chip size="small" color="error" variant="outlined" label={s.high} /> : "—"}</TableCell>
                <TableCell align="right">{s.medium > 0 ? <Chip size="small" color="warning" label={s.medium} /> : "—"}</TableCell>
                <TableCell align="right">{s.total}</TableCell>
                <TableCell>{formatDateTime(s.createdAt)}</TableCell>
              </TableRow>
            ))}
            {rollup.length === 0 && (
              <TableRow><TableCell colSpan={7}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                  No completed scans yet. Update the CVE database, then scan a host.
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {scanOpen && <ScanDialog onClose={() => setScanOpen(false)} onStarted={() => { setScanOpen(false); refresh(); }} />}
      {findingsScan && <FindingsDialog scanId={findingsScan} onClose={() => setFindingsScan(null)} />}
    </Box>
  );
}

function DbStatusCard({ canConfig }: { canConfig: boolean }) {
  const { data: status = "", refetch } = useQuery({ queryKey: ["vuln-db"], queryFn: vulnDbStatus, retry: false });
  const [msg, setMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const update = useMutation({
    mutationFn: vulnDbUpdate,
    onSuccess: (o) => { setMsg("Database updated." + (o ? ` ${o.split("\n")[0]}` : "")); void refetch(); },
    onError: (e) => {
      const detail = ((e as { response?: { data?: { error?: string } } })?.response?.data?.error || "").split("\n")[0].slice(0, 240);
      // Surface the scanner's actual error (permissions, DNS, egress, etc.) rather
      // than assuming a single cause. Offer the offline path as the fallback.
      setMsg((detail ? `Online update failed: ${detail}` : "Online update failed.")
        + " If the scanner cannot reach the internet, use \"Import DB\" with a Grype database archive instead.");
    },
  });
  const importMut = useMutation({
    mutationFn: (f: File) => vulnDbImport(f),
    onSuccess: () => { setMsg("Database imported."); void refetch(); },
    onError: () => setMsg("Import failed — check the archive is a Grype DB export."),
  });

  return (
    <Paper variant="outlined" sx={{ p: 1.5, mb: 2 }}>
      <Stack direction="row" alignItems="center" spacing={2} flexWrap="wrap">
        <Typography variant="subtitle2">CVE database</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "monospace", flexGrow: 1, whiteSpace: "pre-wrap" }}>
          {status ? status.split("\n").filter(Boolean).slice(0, 3).join(" · ") : "status unavailable"}
        </Typography>
        {canConfig && (
          <>
            <Button size="small" variant="outlined" disabled={update.isPending} onClick={() => update.mutate()}>
              {update.isPending ? "Updating…" : "Update online"}
            </Button>
            <Button size="small" disabled={importMut.isPending} onClick={() => fileRef.current?.click()}>
              {importMut.isPending ? "Importing…" : "Import offline"}
            </Button>
            <input ref={fileRef} type="file" hidden accept=".tar.gz,.tar,application/gzip"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) importMut.mutate(f); e.target.value = ""; }} />
          </>
        )}
      </Stack>
      {msg && <Alert severity="info" sx={{ mt: 1, py: 0 }} onClose={() => setMsg(null)}>{msg}</Alert>}
    </Paper>
  );
}

function ScanDialog({ onClose, onStarted }: { onClose: () => void; onStarted: () => void }) {
  const { data: hostsResp } = useQuery({ queryKey: ["hosts"], queryFn: listHosts });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const hosts = hostsResp?.hosts ?? [];
  const [mode, setMode] = useState<"host" | "group">("host");
  const [hostId, setHostId] = useState<string>("");
  const [groupId, setGroupId] = useState<string>("");
  const [err, setErr] = useState<string | null>(null);

  const start = useMutation({
    mutationFn: () => triggerVulnScan(mode === "host" ? { hostId } : { groupId }),
    onSuccess: onStarted,
    onError: (e) => {
      const detail = ((e as { response?: { data?: { error?: string } } })?.response?.data?.error || "").slice(0, 200);
      setErr(detail ? `Could not start the scan: ${detail}` : "Could not start the scan.");
    },
  });

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Run vulnerability scan</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <TextField select size="small" label="Target" value={mode} onChange={(e) => setMode(e.target.value as "host" | "group")}>
            <MenuItem value="host">A single host</MenuItem>
            <MenuItem value="group">All hosts in a group</MenuItem>
          </TextField>
          {mode === "host" ? (
            <Autocomplete
              size="small" options={hosts} getOptionLabel={(h) => h.hostname}
              onChange={(_, v) => setHostId(v?.id ?? "")}
              renderInput={(p) => <TextField {...p} label="Host" />}
            />
          ) : (
            <Autocomplete
              size="small" options={groups} getOptionLabel={(g) => g.name}
              onChange={(_, v) => setGroupId(v?.id ?? "")}
              renderInput={(p) => <TextField {...p} label="Group" />}
            />
          )}
          <Typography variant="caption" color="text.secondary">
            Read-only: Linux hosts are read over SSH (package database), Windows hosts over WinRM
            (missing security updates). Nothing is installed on the host.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained"
          disabled={start.isPending || (mode === "host" ? !hostId : !groupId)}
          onClick={() => start.mutate()}>
          Start scan
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function FindingsDialog({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const { data, isLoading } = useQuery({ queryKey: ["vuln-scan", scanId], queryFn: () => getVulnScan(scanId) });
  const scan = data?.scan;
  const findings = data?.findings ?? [];
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>
        {scan ? `${scan.hostname} — ${scan.total} findings (max CVSS ${scan.maxCvss.toFixed(1)})` : "Findings"}
      </DialogTitle>
      <DialogContent>
        {isLoading && <CircularProgress size={20} />}
        {scan && (
          <Typography variant="caption" color="text.secondary">
            Scanned {formatDateTime(scan.createdAt)}
            {scan.dbBuiltAt ? ` · CVE DB built ${formatDateTime(scan.dbBuiltAt)}` : ""}
          </Typography>
        )}
        <Divider sx={{ my: 1 }} />
        <Paper variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell>Severity</TableCell>
                <TableCell align="right">CVSS</TableCell>
                <TableCell>CVE</TableCell>
                <TableCell>Package</TableCell>
                <TableCell>Installed</TableCell>
                <TableCell>Fixed in</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {findings.map((f: VulnFinding, i) => (
                <TableRow key={`${f.cve}-${f.package}-${i}`}>
                  <TableCell><Chip size="small" color={SEV_COLOR[f.severity] ?? "default"} label={f.severity} /></TableCell>
                  <TableCell align="right">{f.cvssScore > 0 ? f.cvssScore.toFixed(1) : "—"}</TableCell>
                  <TableCell>
                    {f.dataSource ? (
                      <a href={f.dataSource} target="_blank" rel="noopener noreferrer">{f.cve}</a>
                    ) : f.cve}
                  </TableCell>
                  <TableCell>{f.package}</TableCell>
                  <TableCell><code>{f.installedVersion}</code></TableCell>
                  <TableCell>{f.fixedVersion ? <code>{f.fixedVersion}</code> : <Typography variant="caption" color="text.secondary">no fix</Typography>}</TableCell>
                </TableRow>
              ))}
              {!isLoading && findings.length === 0 && (
                <TableRow><TableCell colSpan={6}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>No vulnerabilities found. 🎉</Typography>
                </TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </Paper>
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}
