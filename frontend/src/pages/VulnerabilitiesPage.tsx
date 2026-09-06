import { useRef, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Dialog, DialogActions,
  DialogContent, DialogTitle, Divider, FormControlLabel, MenuItem, Paper, Stack, Switch, Table,
  Snackbar, TableBody, TableCell, TableHead, TableRow, TextField, ToggleButton,
  ToggleButtonGroup, Tooltip, Typography,
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
  downloadScanSbom, isKernelSourceFinding, vulnComponent,
  vulnDbStatus, vulnDbUpdate, vulnDbImport, msrcStatus, msrcUpdate, msrcImport, type VulnFinding,
  type FixState, type VulnScan,
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
    <Box sx={{ maxWidth: 1280 }}>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h5">Vulnerabilities</Typography>
          <Typography variant="body2" color="text.secondary">
            Linux hosts: match installed packages against a CVE database (Grype), scored by CVSS.
            Windows hosts: missing Microsoft security updates (via MSRC) plus curated third-party apps
            (installed software → CPE → Grype/NVD).
          </Typography>
        </Box>
        <Tooltip title="Refresh"><Button startIcon={<RefreshIcon />} onClick={refresh} sx={{ mr: 1 }}>Refresh</Button></Tooltip>
        <Button variant="contained" startIcon={<SecurityIcon />} onClick={() => setScanOpen(true)}>Scan hosts</Button>
      </Stack>

      <DbStatusCard canConfig={canConfig} />
      <MsrcCard canConfig={canConfig} />

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
      <FleetHeadline scans={rollup} />
      <Paper variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            {/* Two header rows so the split is impossible to miss: everything under
                "Actionable now" is work, everything under "Exposure (no fix
                available)" is not. Reading the old table top-to-bottom gave the
                opposite impression — the reddest numbers were the ones nobody
                could do anything about. */}
            <TableRow>
              <TableCell />
              <TableCell align="center" colSpan={4} sx={{ borderLeft: 1, borderColor: "divider" }}>
                <Typography variant="caption" sx={{ fontWeight: 700 }}>Actionable now</Typography>
              </TableCell>
              <TableCell align="center" colSpan={3} sx={{ borderLeft: 1, borderColor: "divider" }}>
                <Typography variant="caption" color="text.secondary">Exposure (no fix available)</Typography>
              </TableCell>
              <TableCell />
            </TableRow>
            <TableRow>
              <TableCell>Host</TableCell>
              <TableCell align="right" sx={{ borderLeft: 1, borderColor: "divider" }}>
                <Tooltip title="CVEs with an available fix — what you can patch right now. Zero means this host is fully patched; everything to the right is unfixed upstream, not a missed patch.">
                  <span>Fixable</span>
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                <Tooltip title="Fixable CVEs rated Critical. This is the number to act on — not the raw Critical count, which includes CVEs no upgrade will ever clear.">
                  <span>Crit</span>
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                <Tooltip title="Fixable CVEs rated High.">
                  <span>High</span>
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                <Tooltip title="Worst CVSS among the FIXABLE CVEs — how urgent today's patching is. (Plain max CVSS is 10.0 on essentially every Linux host, so it said nothing.)">
                  <span>Worst</span>
                </Tooltip>
              </TableCell>
              <TableCell align="right" sx={{ borderLeft: 1, borderColor: "divider" }}>
                <Tooltip title="Critical and High CVEs with no fix available: acknowledged upstream but unpatched, or assessed and deliberately not fixed. Real exposure, but not work you can do today.">
                  <span>Unfixed C / H</span>
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                <Tooltip title="CVEs the distro assessed and decided not to fix (e.g. Debian no-DSA). No upgrade will ever clear these — they inflate the total but are not work.">
                  <span>Won't fix</span>
                </Tooltip>
              </TableCell>
              <TableCell align="right">
                <Tooltip title="Distinct CVEs affecting this host. A CVE spanning several binary packages counts once.">
                  <span>Total</span>
                </Tooltip>
              </TableCell>
              <TableCell>Scanned</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {rollup.map((s) => (
              <TableRow key={s.id} hover sx={{ cursor: "pointer" }} onClick={() => setFindingsScan(s.id)}>
                <TableCell>{s.hostname}</TableCell>
                <TableCell align="right" sx={{ borderLeft: 1, borderColor: "divider" }}>
                  {s.fixable > 0
                    ? <Chip size="small" color="info" label={s.fixable} />
                    : <Chip size="small" color="success" variant="outlined" label="0" />}
                </TableCell>
                <TableCell align="right">
                  {s.fixableCritical > 0 ? <Chip size="small" color="error" label={s.fixableCritical} /> : "—"}
                </TableCell>
                <TableCell align="right">
                  {s.fixableHigh > 0 ? <Chip size="small" color="error" variant="outlined" label={s.fixableHigh} /> : "—"}
                </TableCell>
                <TableCell align="right">
                  {s.fixableMaxCvss > 0
                    ? <Chip size="small" color={cvssColor(s.fixableMaxCvss)} label={s.fixableMaxCvss.toFixed(1)} />
                    : <Typography variant="body2" color="text.secondary">—</Typography>}
                </TableCell>
                <TableCell align="right" sx={{ borderLeft: 1, borderColor: "divider" }}>
                  <Typography variant="body2" color="text.secondary">
                    {s.critical - s.fixableCritical} / {s.high - s.fixableHigh}
                  </Typography>
                </TableCell>
                <TableCell align="right">
                  <Typography variant="body2" color="text.secondary">{s.wontFix > 0 ? s.wontFix : "—"}</Typography>
                </TableCell>
                <TableCell align="right">
                  <Typography variant="body2" color="text.secondary">{s.total}</Typography>
                </TableCell>
                <TableCell>{formatDateTime(s.createdAt)}</TableCell>
              </TableRow>
            ))}
            {rollup.length === 0 && (
              <TableRow><TableCell colSpan={9}>
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

// FleetHeadline answers the page's actual question — "is there anything to do?" —
// before any row is read. Without it the eye lands on the biggest red number in the
// table, which on a patched fleet is the count of CVEs nobody can fix.
function FleetHeadline({ scans }: { scans: VulnScan[] }) {
  if (scans.length === 0) return null;
  const sum = (pick: (s: VulnScan) => number) => scans.reduce((n, s) => n + pick(s), 0);
  const fixable = sum((s) => s.fixable);
  const fixableCrit = sum((s) => s.fixableCritical);
  const fixableHigh = sum((s) => s.fixableHigh);
  const unfixedCrit = sum((s) => s.critical - s.fixableCritical);
  const affected = scans.filter((s) => s.fixable > 0).length;
  // The newest scan in the roll-up: every row is one host's latest, so the most
  // recent of them is how fresh the picture as a whole is.
  const scanned = scans.reduce((a, s) => (s.createdAt > a ? s.createdAt : a), scans[0].createdAt);

  return (
    <Alert severity={fixable === 0 ? "success" : fixableCrit > 0 ? "error" : "warning"} sx={{ mb: 2 }}>
      {fixable === 0 ? (
        <>
          <strong>Nothing outstanding.</strong> No fixable CVEs across {scans.length} host
          {scans.length > 1 ? "s" : ""}. The {unfixedCrit.toLocaleString()} critical CVEs below have no
          fix available — they are unpatched or won't-fix upstream, not missed patches.
        </>
      ) : (
        <>
          <strong>{fixable.toLocaleString()} fixable CVE{fixable > 1 ? "s" : ""}</strong> on {affected} of{" "}
          {scans.length} hosts
          {fixableCrit > 0 || fixableHigh > 0
            ? ` — ${fixableCrit} critical, ${fixableHigh} high.`
            : " (none critical or high)."}{" "}
          A further {unfixedCrit.toLocaleString()} critical CVEs have no fix available.
        </>
      )}{" "}
      <Typography variant="caption" color="text.secondary" component="span">
        Latest scan {formatDateTime(scanned)}.
      </Typography>
    </Alert>
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

// MsrcCard manages the Windows CVE mapping (Microsoft Security Update Guide): its
// load status, an online update, and an offline import (zip of CVRF JSON, a JSON
// array of docs, or a single CVRF JSON). Without it loaded, Windows scans still run
// but findings lack CVE IDs / severity / CVSS.
function MsrcCard({ canConfig }: { canConfig: boolean }) {
  const { data: status, refetch } = useQuery({ queryKey: ["msrc"], queryFn: msrcStatus, retry: false });
  const [msg, setMsg] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const update = useMutation({
    mutationFn: msrcUpdate,
    onSuccess: (n) => { setMsg(`Updated online — ${n} CVE mappings loaded.`); void refetch(); },
    onError: (e) => {
      const detail = ((e as { response?: { data?: { error?: string } } })?.response?.data?.error || "").slice(0, 240);
      setMsg((detail ? `Online update failed: ${detail}` : "Online update failed.")
        + " If the backend cannot reach api.msrc.microsoft.com, use \"Import offline\" with a CVRF bundle instead.");
    },
  });
  const importMut = useMutation({
    mutationFn: (f: File) => msrcImport(f),
    onSuccess: (n) => { setMsg(`Imported — ${n} CVE mappings loaded.`); void refetch(); },
    onError: () => setMsg("Import failed — expected a zip of CVRF JSON, a JSON array, or a single CVRF JSON document."),
  });

  const summary = status && status.count > 0
    ? `${status.count.toLocaleString()} CVE mappings · ${status.releases} releases${status.latestRelease ? " · latest " + status.latestRelease : ""}`
    : "not loaded — Windows findings will lack CVE/severity until you update or import";

  return (
    <Paper variant="outlined" sx={{ p: 1.5, mb: 2 }}>
      <Stack direction="row" alignItems="center" spacing={2} flexWrap="wrap">
        <Typography variant="subtitle2">Windows CVE data (MSRC)</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "monospace", flexGrow: 1, whiteSpace: "pre-wrap" }}>
          {summary}
        </Typography>
        {canConfig && (
          <>
            <Button size="small" variant="outlined" disabled={update.isPending} onClick={() => update.mutate()}>
              {update.isPending ? "Updating…" : "Update online"}
            </Button>
            <Button size="small" disabled={importMut.isPending} onClick={() => fileRef.current?.click()}>
              {importMut.isPending ? "Importing…" : "Import offline"}
            </Button>
            <input ref={fileRef} type="file" hidden accept=".zip,.json,application/zip,application/json"
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

const SEV_OPTIONS = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];
// Hide the noisiest, least-actionable buckets by default; they're one click away.
const SEV_DEFAULT = ["Critical", "High", "Medium", "Low"];

// RemediationChip renders HOW a finding is fixed on the host. "Remove (orphaned)" is
// the important one: the package is installed but in no repository (a leftover from an
// in-place distro upgrade), so an update will never clear it — it must be purged.
function RemediationChip({ value }: { value?: string }) {
  switch (value) {
    case "update":
      return <Chip size="small" color="info" variant="outlined" label="Update" />;
    case "remove":
      return (
        <Tooltip title="This package is installed but offered by no repository — a leftover from an in-place distribution upgrade. An update can't fix it; remove it (e.g. apt purge).">
          <Chip size="small" color="warning" label="Remove (orphaned)" />
        </Tooltip>
      );
    case "unavailable":
      return (
        <Tooltip title="A fix exists upstream, but this host's package manager isn't offering it — the package is held, Debian marked it no-DSA, or it needs an OS release upgrade.">
          <Chip size="small" variant="outlined" label="No apt fix" />
        </Tooltip>
      );
    default:
      return <Typography variant="caption" color="text.secondary">—</Typography>;
  }
}

// Scans recorded before fix_state existed carry no state; an explicit fixed version
// is a fix regardless.
function fixStateOf(f: VulnFinding): FixState {
  if (f.fixState) return f.fixState;
  return f.fixedVersion ? "fixed" : "unknown";
}

// Distinguishes "acknowledged, no fix yet" from "assessed and deliberately not
// fixed" — both arrive with an empty fixed version but mean different things when
// you are deciding whether there is any work to do.
function FixStateChip({ value }: { value: FixState }) {
  switch (value) {
    case "wont-fix":
      return (
        <Tooltip title="The distro assessed this and decided not to fix it (Debian no-DSA / minor issue). No upgrade will ever clear it.">
          <Chip size="small" variant="outlined" label="Won't fix" />
        </Tooltip>
      );
    case "not-fixed":
      return (
        <Tooltip title="Acknowledged upstream, but no fixed version has shipped yet. Nothing to patch today — recheck after the next CVE DB update.">
          <Chip size="small" variant="outlined" color="warning" label="Not fixed yet" />
        </Tooltip>
      );
    default:
      return <Typography variant="caption" color="text.secondary">unknown</Typography>;
  }
}

// A finding merged across every binary package its source builds. One row per
// (CVE, component) instead of one per (CVE, binary): the same CVE repeated against
// libcpupower1 and linux-cpupower is one vulnerability in one component, and
// listing it twice is what made a patched host's drill-down look endless.
interface GroupedFinding extends VulnFinding {
  component: string;
  packages: string[];
  kernel: boolean;
}

function groupByComponent(findings: VulnFinding[]): GroupedFinding[] {
  const by = new Map<string, GroupedFinding>();
  for (const f of findings) {
    const component = vulnComponent(f);
    const key = `${f.cve} ${component}`;
    const g = by.get(key);
    if (!g) {
      by.set(key, {
        ...f, component, packages: [f.package], kernel: isKernelSourceFinding(f),
      });
      continue;
    }
    if (!g.packages.includes(f.package)) g.packages.push(f.package);
    // Merge the way the backend's summary does, so the drill-down and the roll-up
    // cannot disagree: worst severity and score, most actionable fix state.
    if (f.cvssScore > g.cvssScore) g.cvssScore = f.cvssScore;
    if (SEV_RANK.indexOf(f.severity) >= 0 && SEV_RANK.indexOf(f.severity) < SEV_RANK.indexOf(g.severity)) {
      g.severity = f.severity;
    }
    if (FIX_RANK.indexOf(fixStateOf(f)) < FIX_RANK.indexOf(fixStateOf(g))) {
      g.fixState = fixStateOf(f);
      g.fixedVersion = f.fixedVersion;
      g.installedVersion = f.installedVersion;
      g.remediation = f.remediation;
    }
  }
  return [...by.values()].sort((a, b) => b.cvssScore - a.cvssScore || a.cve.localeCompare(b.cve));
}

const SEV_RANK = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];
const FIX_RANK: FixState[] = ["fixed", "not-fixed", "wont-fix", "unknown"];

function FindingsDialog({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const { data, isLoading } = useQuery({ queryKey: ["vuln-scan", scanId], queryFn: () => getVulnScan(scanId) });
  const [sbomBusy, setSbomBusy] = useState(false);
  const [sbomError, setSbomError] = useState(false);
  const scan = data?.scan;
  const findings = data?.findings ?? [];
  const kernelRelease = data?.kernelRelease ?? "";

  const [fixableOnly, setFixableOnly] = useState(false);
  const [hideWontFix, setHideWontFix] = useState(false);
  const [grouped, setGrouped] = useState(true);
  const [sevs, setSevs] = useState<string[]>(SEV_DEFAULT);
  const sevSet = new Set(sevs.map((s) => s.toLowerCase()));
  const rows: GroupedFinding[] = grouped
    ? groupByComponent(findings)
    : findings.map((f) => ({ ...f, component: vulnComponent(f), packages: [f.package], kernel: isKernelSourceFinding(f) }));
  const shown = rows.filter(
    (f) =>
      sevSet.has((f.severity || "unknown").toLowerCase()) &&
      (!fixableOnly || fixStateOf(f) === "fixed") &&
      (!hideWontFix || fixStateOf(f) !== "wont-fix"),
  );
  // The findings list is per CVE-on-package; the scan's total counts CVEs. Show both
  // so "72 CVEs / 154 rows" doesn't read as an inconsistency.
  const distinctShown = new Set(shown.map((f) => f.cve)).size;
  // Kernel CVEs that arrived attributed to a userspace helper. Worth calling out
  // explicitly: on a stock Debian host these are routinely the single largest block
  // of criticals, and nothing about the package name says "kernel".
  const kernelRows = shown.filter((f) => f.kernel);
  const kernelMatchedAt = kernelRows[0]?.installedVersion ?? "";

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>
        {scan
          ? `${scan.hostname} — ${scan.fixable} fixable of ${scan.total} CVEs` +
            (scan.fixableCritical + scan.fixableHigh > 0
              ? ` (${scan.fixableCritical} critical, ${scan.fixableHigh} high)`
              : "")
          : "Findings"}
      </DialogTitle>
      <DialogContent>
        {isLoading && <CircularProgress size={20} />}
        {scan && (
          <Typography variant="caption" color="text.secondary">
            Scanned {formatDateTime(scan.createdAt)}
            {scan.dbBuiltAt ? ` · CVE DB built ${formatDateTime(scan.dbBuiltAt)}` : ""}
            {kernelRelease ? ` · running kernel ${kernelRelease}` : ""}
            {scan.wontFix > 0 ? ` · ${scan.wontFix} marked won't-fix upstream` : ""}
            {scan.fixable === 0 && scan.total > 0
              ? " — nothing outstanding: every remaining CVE is unfixed upstream, not a missed patch."
              : ""}
          </Typography>
        )}
        {kernelRows.length > 0 && (
          <Alert severity="info" sx={{ mt: 1 }}>
            <strong>{kernelRows.length} of these are Linux kernel CVEs.</strong> They are listed against{" "}
            {[...new Set(kernelRows.map((f) => f.packages.join(", ")))].slice(0, 3).join(", ")} because the
            distribution builds those helpers from the same <code>linux</code> source package its security
            tracker files kernel CVEs under — so grype matches the whole kernel CVE list against them, at{" "}
            {kernelMatchedAt ? <code>{kernelMatchedAt}</code> : "that package's version"}
            {kernelRelease ? <> while the host is running <code>{kernelRelease}</code></> : null}. The
            vulnerabilities are real and concern the kernel, not the helper package; patch and reboot the
            kernel to clear them.
          </Alert>
        )}
        <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" sx={{ mt: 1 }}>
          <FormControlLabel
            control={<Switch size="small" checked={fixableOnly} onChange={(e) => setFixableOnly(e.target.checked)} />}
            label="Fixable only"
          />
          <FormControlLabel
            control={<Switch size="small" checked={hideWontFix} onChange={(e) => setHideWontFix(e.target.checked)} />}
            label="Hide won't-fix"
          />
          <Tooltip title="One row per CVE and source package instead of one per binary package. A source package builds many binaries and each repeats the same CVE, so ungrouped lists run roughly twice as long without saying anything more.">
            <FormControlLabel
              control={<Switch size="small" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />}
              label="Group by component"
            />
          </Tooltip>
          <ToggleButtonGroup
            size="small" value={sevs} onChange={(_, v) => setSevs(v as string[])}
            aria-label="severity filter"
          >
            {SEV_OPTIONS.map((s) => (
              <ToggleButton key={s} value={s} sx={{ textTransform: "none", py: 0.2 }}>{s}</ToggleButton>
            ))}
          </ToggleButtonGroup>
          <Typography variant="caption" color="text.secondary">
            showing {shown.length} of {rows.length} {grouped ? "component findings" : "package findings"}{" "}
            ({distinctShown} distinct CVEs)
          </Typography>
        </Stack>
        <Divider sx={{ my: 1 }} />
        <Paper variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>
                <TableCell>Severity</TableCell>
                <TableCell align="right">CVSS</TableCell>
                <TableCell>CVE</TableCell>
                <TableCell>{grouped ? "Component" : "Package"}</TableCell>
                <TableCell>Installed</TableCell>
                <TableCell>Fixed in</TableCell>
                <TableCell>Fix</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {shown.map((f, i) => (
                <TableRow key={`${f.cve}-${f.component}-${i}`}>
                  <TableCell><Chip size="small" color={SEV_COLOR[f.severity] ?? "default"} label={f.severity} /></TableCell>
                  <TableCell align="right">{f.cvssScore > 0 ? f.cvssScore.toFixed(1) : "—"}</TableCell>
                  <TableCell>
                    {f.dataSource ? (
                      <a href={f.dataSource} target="_blank" rel="noopener noreferrer">{f.cve}</a>
                    ) : f.cve}
                  </TableCell>
                  <TableCell>
                    <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap">
                      <span>{grouped ? f.component : f.package}</span>
                      {f.kernel && (
                        <Tooltip title={`A kernel CVE. The distribution builds ${f.packages.join(", ")} from the ${f.component} source package that kernel CVEs are tracked under, so it is matched here — the kernel is what is affected.`}>
                          <Chip size="small" variant="outlined" color="warning" label="kernel" />
                        </Tooltip>
                      )}
                      {grouped && f.packages.length > 1 && (
                        <Tooltip title={f.packages.join(", ")}>
                          <Chip size="small" variant="outlined" label={`${f.packages.length} pkgs`} />
                        </Tooltip>
                      )}
                    </Stack>
                  </TableCell>
                  <TableCell><code>{f.installedVersion}</code></TableCell>
                  <TableCell>{f.fixedVersion ? <code>{f.fixedVersion}</code> : <FixStateChip value={fixStateOf(f)} />}</TableCell>
                  <TableCell><RemediationChip value={f.remediation} /></TableCell>
                </TableRow>
              ))}
              {!isLoading && shown.length === 0 && (
                <TableRow><TableCell colSpan={7}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                    {findings.length === 0 ? "No vulnerabilities found. 🎉" : "No findings match the current filters."}
                  </Typography>
                </TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </Paper>
      </DialogContent>
      <DialogActions>
        {/* The SBOM is per scan rather than per host here: this dialog is
            already showing one specific scan, and the inventory it collected is
            the one that produced these findings. */}
        <Button
          disabled={!scan || sbomBusy}
          onClick={async () => {
            if (!scan) return;
            setSbomBusy(true);
            try {
              await downloadScanSbom(scan.id);
            } catch {
              // A scan from before inventory capture, or a host with neither
              // dpkg nor rpm, simply has no document. Saying so beats a silent
              // no-op on a button the user just pressed.
              setSbomError(true);
            } finally {
              setSbomBusy(false);
            }
          }}
        >
          Download SBOM
        </Button>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
      <Snackbar
        open={sbomError}
        autoHideDuration={6000}
        onClose={() => setSbomError(false)}
        message="No SBOM for this scan — it may predate inventory capture, or the host has no supported package manager."
      />
    </Dialog>
  );
}
