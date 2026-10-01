import { useRef, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, CircularProgress, Collapse, Dialog, DialogActions,
  DialogContent, DialogTitle, FormControlLabel, IconButton, MenuItem, Paper, Stack, Switch, Table,
  TableBody, TableCell, TableHead, TableRow, TextField, ToggleButton, ToggleButtonGroup, Tooltip,
  Typography,
} from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import RadarIcon from "@mui/icons-material/Radar";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowUpIcon from "@mui/icons-material/KeyboardArrowUp";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";
import { listHosts } from "../api/hosts";
import { listGroups } from "../api/admin";
import {
  clearFailedNetScans, createNetScanRange, deleteNetScanRange, exposedServices, getNetScan,
  hostNetScans, latestNetScans, listNetScanRanges, listNetScans, listeningNotReachable,
  netScanStatus, netSevColor, netTemplatesImport, netTemplatesUpdate, pathLabel,
  scanNetScanRange, triggerNetScan, updateNetScanRange,
  type ExposedService, type NetFinding, type NetScan, type NetScanRange, type RangeInput,
  type SkippedHost,
} from "../api/netscan";

// The version banner when there is one ("nginx/1.22.1"); fingerprintx's product
// name otherwise. Showing both repeated the same fact twice in different case.
function productLabel(s: { product?: string; version?: string }): string {
  return s.version || s.product || "—";
}

function errText(e: unknown, fallback: string): string {
  const d = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return d ? d.split("\n")[0].slice(0, 300) : fallback;
}

export function StatusChip({ scan }: { scan: Pick<NetScan, "status" | "reason" | "error"> }) {
  switch (scan.status) {
    case "completed":
      return <Chip size="small" color="success" variant="outlined" label="Scanned" />;
    case "unreachable":
      return (
        <Tooltip title={scan.reason || "The address did not answer. Not assessed — this is not a clean result."}>
          <Chip size="small" color="warning" label="Unreachable" />
        </Tooltip>
      );
    case "failed":
      return (
        <Tooltip title={scan.error || "failed"}>
          <Chip size="small" color="error" label="Failed" />
        </Tooltip>
      );
    default:
      return <Chip size="small" label={scan.status === "running" ? "Running…" : "Pending"} />;
  }
}

export function PathChip({ path }: { path: string }) {
  const tip =
    path === "overlay"
      ? "Scanned at the host's overlay address: what the jump host — and so anyone who controls it — can reach."
      : path === "lan"
        ? "Scanned at the host's own address: what anything on its network can reach."
        : "Found by scanning an operator-defined network range.";
  return (
    <Tooltip title={tip}>
      <Chip size="small" variant="outlined" color={path === "overlay" ? "secondary" : "default"} label={pathLabel(path)} />
    </Tooltip>
  );
}

function SevCounts({ s }: { s: Pick<NetScan, "critical" | "high" | "medium" | "low"> }) {
  const parts: [number, string, "error" | "warning" | "info"][] = [
    [s.critical, "C", "error"], [s.high, "H", "error"], [s.medium, "M", "warning"], [s.low, "L", "info"],
  ];
  const any = parts.some(([n]) => n > 0);
  if (!any) return <Typography variant="body2" color="text.secondary">—</Typography>;
  return (
    <Stack direction="row" spacing={0.5}>
      {parts.filter(([n]) => n > 0).map(([n, l, c]) => (
        <Chip key={l} size="small" color={c} variant={l === "H" ? "outlined" : "filled"} label={`${n} ${l}`} />
      ))}
    </Stack>
  );
}

// NetworkScansPage: what the fleet exposes on the network. Gated by Host.Scan;
// ranges and templates by System.Configure.
export function NetworkScansPage() {
  const qc = useQueryClient();
  const canConfig = useAuthStore((s) => s.has("System.Configure"));
  const [scanOpen, setScanOpen] = useState(false);
  const [detail, setDetail] = useState<string | null>(null);
  const [skipped, setSkipped] = useState<SkippedHost[]>([]);

  const { data: rollup = [] } = useQuery({ queryKey: ["net-latest"], queryFn: latestNetScans });
  const { data: recent = [] } = useQuery({
    queryKey: ["net-recent"], queryFn: () => listNetScans(), refetchInterval: 5000,
  });
  const running = recent.filter((s) => s.status === "pending" || s.status === "running");
  const failed = recent.filter((s) => s.status === "failed").slice(0, 5);

  const refresh = () => {
    for (const k of ["net-latest", "net-recent", "net-exposed", "net-ranges"]) {
      void qc.invalidateQueries({ queryKey: [k] });
    }
  };
  const clearFailed = useMutation({
    mutationFn: clearFailedNetScans,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["net-recent"] }),
  });

  return (
    <Box sx={{ maxWidth: 1280 }}>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="h5">Network exposure</Typography>
          <Typography variant="body2" color="text.secondary">
            What each host answers on from the network — every TCP port, on its overlay address (or its LAN
            address when it has none) — what is serving there, and whether it is vulnerable or misconfigured.
            The other half of the package scans on the Vulnerabilities page, which see what is installed but not
            what is reachable.
          </Typography>
        </Box>
        <Tooltip title="Refresh"><Button startIcon={<RefreshIcon />} onClick={refresh} sx={{ mr: 1 }}>Refresh</Button></Tooltip>
        <Button variant="contained" startIcon={<RadarIcon />} onClick={() => setScanOpen(true)}>Scan hosts</Button>
      </Stack>

      <ScannerCard canConfig={canConfig} />

      {skipped.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }} onClose={() => setSkipped([])}>
          Not scanned: {skipped.map((s) => `${s.hostname} — ${s.reason}`).join("; ")}
        </Alert>
      )}
      {running.length > 0 && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {running.length} address{running.length > 1 ? "es" : ""} being scanned… a full TCP sweep and the
          vulnerability checks take a few minutes per address.
        </Alert>
      )}
      {failed.length > 0 && (
        <Alert
          severity="warning" sx={{ mb: 2 }}
          action={<Button color="inherit" size="small" disabled={clearFailed.isPending} onClick={() => clearFailed.mutate()}>Clear</Button>}
        >
          Recent failures: {failed.map((f) => `${f.hostname || f.target} (${pathLabel(f.path)}): ${f.error || "error"}`).join("; ")}
        </Alert>
      )}

      <Headline scans={rollup} />

      <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>Latest scan per host</Typography>
      <RollupTable scans={rollup} onOpen={setDetail} />

      <ExposedTable onOpen={setDetail} />

      <RangesCard canConfig={canConfig} onOpen={setDetail} />

      {scanOpen && (
        <ScanDialog
          onClose={() => setScanOpen(false)}
          onStarted={(sk) => { setScanOpen(false); setSkipped(sk); refresh(); }}
        />
      )}
      {detail && <NetScanDialog scanId={detail} onClose={() => setDetail(null)} />}
    </Box>
  );
}

// Headline answers "is anything wrong?" before a row is read.
function Headline({ scans }: { scans: NetScan[] }) {
  if (scans.length === 0) return null;
  const done = scans.filter((s) => s.status === "completed");
  const dark = scans.filter((s) => s.status === "unreachable");
  const serious = done.filter((s) => s.critical + s.high > 0);
  const unexpected = done.reduce((n, s) => n + s.unexpected, 0);
  const findings = done.reduce((n, s) => n + s.total, 0);
  const sev = serious.length > 0 ? "error" : findings > 0 || unexpected > 0 ? "warning" : "success";
  return (
    <Alert severity={sev} sx={{ mb: 2 }}>
      {serious.length > 0 ? (
        <><strong>{serious.length} address{serious.length > 1 ? "es" : ""} with critical or high findings</strong>{" "}
          ({serious.map((s) => `${s.hostname || s.target} ${pathLabel(s.path)}`).slice(0, 5).join(", ")}
          {serious.length > 5 ? ", …" : ""}).</>
      ) : findings > 0 ? (
        <><strong>{findings} network finding{findings > 1 ? "s" : ""}</strong>, none critical or high.</>
      ) : (
        <><strong>No network findings</strong> on {done.length} scanned address{done.length === 1 ? "" : "es"}.</>
      )}{" "}
      {unexpected > 0 && <>{unexpected} reachable port{unexpected > 1 ? "s" : ""} the hosts do not account for. </>}
      {dark.length > 0 && (
        <>{dark.length} address{dark.length > 1 ? "es" : ""} did not answer and {dark.length > 1 ? "were" : "was"} not
          assessed.</>
      )}
    </Alert>
  );
}

function RollupTable({ scans, onOpen }: { scans: NetScan[]; onOpen: (id: string) => void }) {
  return (
    <Paper variant="outlined" sx={{ overflowX: "auto", mb: 3 }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Host / address</TableCell>
            <TableCell>Path</TableCell>
            <TableCell>Status</TableCell>
            <TableCell align="right">Open ports</TableCell>
            <TableCell>Findings</TableCell>
            <TableCell align="right">
              <Tooltip title="Ports that answered from the network but that the host's own listener list does not show — a port forward, a NAT rule (Docker with userland-proxy off), or something hiding.">
                <span>Unexpected</span>
              </Tooltip>
            </TableCell>
            <TableCell>Scanned</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {scans.map((s) => (
            <TableRow key={s.id} hover sx={{ cursor: "pointer" }} onClick={() => onOpen(s.id)}>
              <TableCell>
                {s.hostname || s.target}
                {s.hostname && <Typography variant="caption" color="text.secondary" sx={{ ml: 1 }}>{s.target}</Typography>}
              </TableCell>
              <TableCell><PathChip path={s.path} /></TableCell>
              <TableCell><StatusChip scan={s} /></TableCell>
              <TableCell align="right">{s.status === "completed" ? s.openPorts : "—"}</TableCell>
              <TableCell>{s.status === "completed" ? <SevCounts s={s} /> : "—"}</TableCell>
              <TableCell align="right">
                {s.unexpected > 0 ? <Chip size="small" color="warning" label={s.unexpected} /> : "—"}
              </TableCell>
              <TableCell>{formatDateTime(s.finishedAt ?? s.createdAt)}</TableCell>
            </TableRow>
          ))}
          {scans.length === 0 && (
            <TableRow><TableCell colSpan={7}>
              <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                No network scans yet. Make sure the scanner's templates are installed, then scan a host.
              </Typography>
            </TableCell></TableRow>
          )}
        </TableBody>
      </Table>
    </Paper>
  );
}

type PathFilter = "all" | "lan" | "overlay" | "range";

function ExposedTable({ onOpen }: { onOpen: (id: string) => void }) {
  const { data: services = [], isLoading } = useQuery({ queryKey: ["net-exposed"], queryFn: exposedServices });
  const [path, setPath] = useState<PathFilter>("all");
  const [unexpectedOnly, setUnexpectedOnly] = useState(false);
  const [findingsOnly, setFindingsOnly] = useState(false);
  const [q, setQ] = useState("");
  const needle = q.trim().toLowerCase();
  const shown = services.filter((s) =>
    (path === "all" || s.path === path) &&
    (!unexpectedOnly || s.unexpected) &&
    (!findingsOnly || s.findings > 0) &&
    (needle === "" || [s.hostname, s.target, s.service, s.product, s.process, String(s.port)]
      .some((v) => (v ?? "").toLowerCase().includes(needle))),
  );
  return (
    <>
      <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>Exposed services</Typography>
      <Stack direction="row" spacing={2} alignItems="center" flexWrap="wrap" sx={{ mb: 1 }}>
        <ToggleButtonGroup size="small" exclusive value={path} onChange={(_, v) => v && setPath(v as PathFilter)}>
          {(["all", "lan", "overlay", "range"] as PathFilter[]).map((p) => (
            <ToggleButton key={p} value={p} sx={{ textTransform: "none", py: 0.2 }}>{p === "all" ? "All paths" : pathLabel(p)}</ToggleButton>
          ))}
        </ToggleButtonGroup>
        <FormControlLabel control={<Switch size="small" checked={unexpectedOnly} onChange={(e) => setUnexpectedOnly(e.target.checked)} />} label="Unexpected only" />
        <FormControlLabel control={<Switch size="small" checked={findingsOnly} onChange={(e) => setFindingsOnly(e.target.checked)} />} label="With findings" />
        <TextField size="small" placeholder="Filter host, service, process, port" value={q} onChange={(e) => setQ(e.target.value)} sx={{ minWidth: 260 }} />
        <Typography variant="caption" color="text.secondary">showing {shown.length} of {services.length}</Typography>
      </Stack>
      <Paper variant="outlined" sx={{ overflowX: "auto", mb: 3, maxHeight: 520 }}>
        <Table size="small" stickyHeader>
          <TableHead>
            <TableRow>
              <TableCell>Host / address</TableCell>
              <TableCell>Path</TableCell>
              <TableCell align="right">Port</TableCell>
              <TableCell>Service</TableCell>
              <TableCell>Product / version</TableCell>
              <TableCell>Process</TableCell>
              <TableCell>Findings</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {isLoading && <TableRow><TableCell colSpan={7}><CircularProgress size={18} /></TableCell></TableRow>}
            {shown.map((s: ExposedService) => (
              <TableRow key={`${s.scanId}-${s.proto}-${s.port}`} hover sx={{ cursor: "pointer" }} onClick={() => onOpen(s.scanId)}>
                <TableCell>{s.hostname || s.target}</TableCell>
                <TableCell>
                  <PathChip path={s.path} />
                </TableCell>
                <TableCell align="right"><code>{s.port}/{s.proto}</code></TableCell>
                <TableCell>
                  <Stack direction="row" spacing={0.5} alignItems="center">
                    <span>{s.service || "—"}</span>
                    {s.tls && <Chip size="small" variant="outlined" label="TLS" />}
                  </Stack>
                </TableCell>
                <TableCell>
                  <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                    {productLabel(s)}
                  </Typography>
                </TableCell>
                <TableCell>
                  {s.unexpected ? (
                    <Tooltip title="Reachable, but no socket on the host is bound to this port. A port forward or NAT rule — or something not showing in ss.">
                      <Chip size="small" color="warning" label="unexpected" />
                    </Tooltip>
                  ) : (s.process || "—")}
                </TableCell>
                <TableCell>
                  {s.findings > 0
                    ? <Chip size="small" color={netSevColor(s.worstSeverity)} label={`${s.findings} · ${s.worstSeverity}`} />
                    : "—"}
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && shown.length === 0 && (
              <TableRow><TableCell colSpan={7}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                  {services.length === 0 ? "Nothing scanned yet." : "No services match the current filters."}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>
    </>
  );
}

function ScannerCard({ canConfig }: { canConfig: boolean }) {
  const { data: st, refetch, isLoading: stLoading, error: stError } = useQuery({
    queryKey: ["net-status"], queryFn: netScanStatus, retry: false,
  });
  const [msg, setMsg] = useState<{ sev: "info" | "error"; text: string } | null>(null);
  const fileRef = useRef<HTMLInputElement | null>(null);
  const update = useMutation({
    mutationFn: netTemplatesUpdate,
    onSuccess: (t) => { setMsg({ sev: "info", text: `Templates updated${t.version ? ` to ${t.version}` : ""}.` }); void refetch(); },
    onError: (e) => setMsg({
      sev: "error",
      text: `${errText(e, "Online update failed.")} If the scanner cannot reach the internet, use "Import offline" with a nuclei-templates archive.`,
    }),
  });
  const importMut = useMutation({
    mutationFn: (f: File) => netTemplatesImport(f),
    onSuccess: () => { setMsg({ sev: "info", text: "Templates imported." }); void refetch(); },
    onError: (e) => setMsg({ sev: "error", text: errText(e, "Import failed — expected a .tar.gz of the nuclei-templates repository.") }),
  });

  let summary: string;
  let sev: "success" | "warning" | "error" | "default" = "success";
  if (stLoading) {
    summary = "checking…";
    sev = "default";
  } else if (!st) {
    summary = errText(stError, "status unavailable");
    sev = "error";
  } else if (!st.configured) {
    summary = "not configured — set PROV_NETSCAN_TOKEN (the same value for the backend and the net-scanner) and restart both";
    sev = "error";
  } else if (st.healthError) {
    summary = st.healthError;
    sev = "error";
  } else {
    const t = st.templates;
    const parts = [
      t?.present ? `templates ${t.version || "installed"}${t.updatedAt ? ` (${formatDateTime(t.updatedAt)})` : ""}` : "no templates installed",
      st.health?.overlay === "ok" ? "overlay reachable"
        : st.health?.overlay === "no-route" ? "NO route to the overlay — restart the net-scanner if the jump host was recreated"
          : "overlay not reachable in this deployment (LAN only)",
    ];
    if (t?.excludedCredentialTemplates) parts.push(`${t.excludedCredentialTemplates} credential-guessing templates excluded`);
    summary = parts.join(" · ");
    if (!t?.present || st.health?.overlay === "no-route") sev = "error";
    else if (st.templatesStale) sev = "warning";
  }

  return (
    <Paper variant="outlined" sx={{ p: 1.5, mb: 2 }}>
      <Stack direction="row" alignItems="center" spacing={2} flexWrap="wrap">
        <Typography variant="subtitle2">Network scanner</Typography>
        <Chip size="small" color={sev} variant="outlined"
          label={{ success: "ready", warning: "stale", error: "attention", default: "…" }[sev]} />
        <Typography variant="body2" color="text.secondary" sx={{ flexGrow: 1 }}>{summary}</Typography>
        {canConfig && st?.configured && (
          <>
            <Button size="small" variant="outlined" disabled={update.isPending} onClick={() => update.mutate()}>
              {update.isPending ? "Updating…" : "Update templates"}
            </Button>
            <Button size="small" disabled={importMut.isPending} onClick={() => fileRef.current?.click()}>
              {importMut.isPending ? "Importing…" : "Import offline"}
            </Button>
            <input ref={fileRef} type="file" hidden accept=".tar.gz,.tgz,.tar,application/gzip"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) importMut.mutate(f); e.target.value = ""; }} />
          </>
        )}
      </Stack>
      {st?.templatesStale && (
        <Typography variant="caption" color="warning.main">
          The templates are more than a day and a half old; the nightly refresh may be failing, and checks published since are missing.
        </Typography>
      )}
      {msg && <Alert severity={msg.sev} sx={{ mt: 1, py: 0 }} onClose={() => setMsg(null)}>{msg.text}</Alert>}
    </Paper>
  );
}

function ScanDialog({ onClose, onStarted }: { onClose: () => void; onStarted: (skipped: SkippedHost[]) => void }) {
  const { data: hostsResp } = useQuery({ queryKey: ["hosts"], queryFn: listHosts });
  const { data: groups = [] } = useQuery({ queryKey: ["groups"], queryFn: listGroups });
  const hosts = hostsResp?.hosts ?? [];
  const [mode, setMode] = useState<"host" | "group">("host");
  const [hostId, setHostId] = useState("");
  const [groupId, setGroupId] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const start = useMutation({
    mutationFn: () => triggerNetScan(mode === "host" ? { hostId } : { groupId }),
    onSuccess: (r) => onStarted(r.skipped),
    onError: (e) => setErr(`Could not start the scan: ${errText(e, "unknown error")}`),
  });
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Run network scan</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <TextField select size="small" label="Target" value={mode} onChange={(e) => setMode(e.target.value as "host" | "group")}>
            <MenuItem value="host">A single host</MenuItem>
            <MenuItem value="group">All hosts in a group</MenuItem>
          </TextField>
          {mode === "host" ? (
            <Autocomplete size="small" options={hosts} getOptionLabel={(h) => h.hostname}
              onChange={(_, v) => setHostId(v?.id ?? "")} renderInput={(p) => <TextField {...p} label="Host" />} />
          ) : (
            <Autocomplete size="small" options={groups} getOptionLabel={(g) => g.name}
              onChange={(_, v) => setGroupId(v?.id ?? "")} renderInput={(p) => <TextField {...p} label="Group" />} />
          )}
          <Typography variant="caption" color="text.secondary">
            Each host is scanned from the network on its overlay address — or its LAN address when it has none: all
            65,535 TCP ports, service identification, and vulnerability and misconfiguration checks. Nothing that guesses credentials or could
            disrupt a service is ever run. Traffic identifies itself as Provenance-NetScan. The host's own listener list
            is read over SSH or WinRM to compare against.
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={start.isPending || (mode === "host" ? !hostId : !groupId)} onClick={() => start.mutate()}>
          Start scan
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// --- ranges ------------------------------------------------------------------------

function RangesCard({ canConfig, onOpen }: { canConfig: boolean; onOpen: (id: string) => void }) {
  const qc = useQueryClient();
  const { data: ranges = [] } = useQuery({ queryKey: ["net-ranges"], queryFn: listNetScanRanges });
  const [editing, setEditing] = useState<NetScanRange | "new" | null>(null);
  const [viewing, setViewing] = useState<NetScanRange | null>(null);
  const [msg, setMsg] = useState<{ sev: "info" | "error"; text: string } | null>(null);
  const del = useMutation({
    mutationFn: deleteNetScanRange,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["net-ranges"] }),
    onError: (e) => setMsg({ sev: "error", text: errText(e, "Could not delete the range.") }),
  });
  const scan = useMutation({
    mutationFn: scanNetScanRange,
    onSuccess: () => {
      setMsg({ sev: "info", text: "Range scan started. Live addresses are found first, then each is scanned in full." });
      void qc.invalidateQueries({ queryKey: ["net-recent"] });
    },
    onError: (e) => setMsg({ sev: "error", text: errText(e, "Could not start the range scan.") }),
  });
  return (
    <>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Network ranges</Typography>
          <Typography variant="caption" color="text.secondary">
            For devices Provenance does not manage — switches, printers, appliances, the gateway. Live addresses are
            found with the common ports, then each is scanned like a host (without a listener list to compare to).
          </Typography>
        </Box>
        {canConfig && <Button size="small" variant="outlined" onClick={() => setEditing("new")}>Add range</Button>}
      </Stack>
      {msg && <Alert severity={msg.sev} sx={{ mb: 1 }} onClose={() => setMsg(null)}>{msg.text}</Alert>}
      <Paper variant="outlined" sx={{ overflowX: "auto", mb: 3 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Network</TableCell>
              <TableCell>Enabled</TableCell>
              <TableCell>Last scan</TableCell>
              <TableCell align="right">Live</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {ranges.map((r) => (
              <TableRow key={r.id} hover>
                <TableCell>
                  {r.name}
                  {r.note && <Typography variant="caption" color="text.secondary" sx={{ display: "block" }}>{r.note}</Typography>}
                </TableCell>
                <TableCell><code>{r.cidr}</code></TableCell>
                <TableCell>{r.enabled ? "yes" : <Chip size="small" label="disabled" />}</TableCell>
                <TableCell>{r.lastScan ? formatDateTime(r.lastScan) : "never"}</TableCell>
                <TableCell align="right">
                  {r.lastScan ? <Button size="small" onClick={() => setViewing(r)}>{r.lastLive}</Button> : "—"}
                </TableCell>
                <TableCell align="right" sx={{ whiteSpace: "nowrap" }}>
                  <Tooltip title="Scan now">
                    <span><IconButton size="small" disabled={scan.isPending} onClick={() => scan.mutate(r.id)}><PlayArrowIcon fontSize="small" /></IconButton></span>
                  </Tooltip>
                  {canConfig && (
                    <>
                      <IconButton size="small" onClick={() => setEditing(r)}><EditIcon fontSize="small" /></IconButton>
                      <IconButton size="small" disabled={del.isPending} onClick={() => del.mutate(r.id)}><DeleteIcon fontSize="small" /></IconButton>
                    </>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {ranges.length === 0 && (
              <TableRow><TableCell colSpan={6}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                  No ranges defined.{canConfig ? " Add one to scan devices that are not managed hosts." : ""}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>
      {editing && <RangeDialog range={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      {viewing && <RangeScansDialog range={viewing} onClose={() => setViewing(null)} onOpen={onOpen} />}
    </>
  );
}

function RangeDialog({ range, onClose }: { range: NetScanRange | null; onClose: () => void }) {
  const qc = useQueryClient();
  const [form, setForm] = useState<RangeInput>({
    name: range?.name ?? "", cidr: range?.cidr ?? "", note: range?.note ?? "", enabled: range?.enabled ?? true,
  });
  const [err, setErr] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: () => (range ? updateNetScanRange(range.id, form) : createNetScanRange(form)),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["net-ranges"] }); onClose(); },
    onError: (e) => setErr(errText(e, "Could not save the range.")),
  });
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{range ? "Edit range" : "Add network range"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          {err && <Alert severity="error">{err}</Alert>}
          <TextField size="small" label="Name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <TextField size="small" label="Network (CIDR)" placeholder="10.0.2.0/24" value={form.cidr}
            helperText="At most 1,024 addresses (a /22). Loopback, link-local and multicast are refused."
            onChange={(e) => setForm({ ...form, cidr: e.target.value })} />
          <TextField size="small" label="Note" value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
          <FormControlLabel control={<Switch checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />}
            label="Included in scheduled range scans" />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending || !form.name.trim() || !form.cidr.trim()} onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}

function RangeScansDialog({ range, onClose, onOpen }: { range: NetScanRange; onClose: () => void; onOpen: (id: string) => void }) {
  const { data: scans = [], isLoading } = useQuery({
    queryKey: ["net-range-scans", range.id], queryFn: () => listNetScans({ rangeId: range.id }),
  });
  // The latest run only: what the range looks like now.
  const latestRun = scans[0]?.runId;
  const shown = scans.filter((s) => s.runId === latestRun);
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>{range.name} — <code>{range.cidr}</code></DialogTitle>
      <DialogContent>
        {isLoading && <CircularProgress size={18} />}
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Address</TableCell><TableCell>Managed host</TableCell><TableCell>Status</TableCell>
              <TableCell align="right">Open</TableCell><TableCell>Findings</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {shown.map((s) => (
              <TableRow key={s.id} hover sx={{ cursor: "pointer" }} onClick={() => onOpen(s.id)}>
                <TableCell><code>{s.target}</code></TableCell>
                <TableCell>{s.hostname || <Typography variant="caption" color="text.secondary">unmanaged</Typography>}</TableCell>
                <TableCell><StatusChip scan={s} /></TableCell>
                <TableCell align="right">{s.status === "completed" ? s.openPorts : "—"}</TableCell>
                <TableCell>{s.status === "completed" ? <SevCounts s={s} /> : "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}

// --- scan detail -----------------------------------------------------------------------

export function CorroborationChip({ value }: { value?: string }) {
  if (value === "confirmed") {
    return (
      <Tooltip title="The host's package scan reports the same CVE: the vulnerable version is really installed, and this check reached it over the network.">
        <Chip size="small" color="error" label="confirmed" />
      </Tooltip>
    );
  }
  if (value === "banner-only") {
    return (
      <Tooltip title="Matched from a version banner, and the host's package scan — which knows the real installed version, including distro backports — does not report this CVE. Most likely already patched.">
        <Chip size="small" variant="outlined" label="banner-only" />
      </Tooltip>
    );
  }
  return null;
}

function FindingRow({ f }: { f: NetFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <TableRow hover>
        <TableCell padding="checkbox">
          <IconButton size="small" onClick={() => setOpen(!open)} aria-label="details">
            {open ? <KeyboardArrowUpIcon fontSize="small" /> : <KeyboardArrowDownIcon fontSize="small" />}
          </IconButton>
        </TableCell>
        <TableCell><Chip size="small" color={netSevColor(f.severity)} label={f.severity} /></TableCell>
        <TableCell>{f.name}</TableCell>
        <TableCell><code>{f.port ? `${f.port}/${f.proto}` : f.proto}</code></TableCell>
        <TableCell>
          <Stack direction="row" spacing={0.5} alignItems="center" flexWrap="wrap">
            {(f.cves ?? []).map((c) => (
              <a key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer">{c}</a>
            ))}
            <CorroborationChip value={f.corroboration} />
          </Stack>
        </TableCell>
        <TableCell align="right">{f.cvssScore > 0 ? f.cvssScore.toFixed(1) : "—"}</TableCell>
      </TableRow>
      <TableRow>
        <TableCell colSpan={6} sx={{ py: 0, borderBottom: open ? undefined : "none" }}>
          <Collapse in={open} unmountOnExit>
            <Box sx={{ py: 1 }}>
              {f.matchedAt && <Typography variant="body2"><strong>Matched at:</strong> <code>{f.matchedAt}</code></Typography>}
              {f.description && <Typography variant="body2" sx={{ mt: 0.5 }}>{f.description}</Typography>}
              {f.remediation && <Typography variant="body2" sx={{ mt: 0.5 }}><strong>Fix:</strong> {f.remediation}</Typography>}
              {(f.extracted ?? []).length > 0 && (
                <Typography variant="body2" sx={{ mt: 0.5 }}><strong>Evidence:</strong> <code>{(f.extracted ?? []).join(" · ")}</code></Typography>
              )}
              {(f.references ?? []).length > 0 && (
                <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
                  {(f.references ?? []).slice(0, 5).map((r) => (
                    <div key={r}><a href={r} target="_blank" rel="noopener noreferrer">{r}</a></div>
                  ))}
                </Typography>
              )}
              <Typography variant="caption" color="text.secondary">check: {f.templateId}</Typography>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

export function NetScanDialog({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const { data: scan, isLoading } = useQuery({ queryKey: ["net-scan", scanId], queryFn: () => getNetScan(scanId) });
  // The host's latest scans, so "listening but not reachable" is measured against them.
  const { data: hostScans = [] } = useQuery({
    queryKey: ["net-host", scan?.hostId], queryFn: () => hostNetScans(scan!.hostId!), enabled: !!scan?.hostId,
  });
  const quiet = scan ? listeningNotReachable(scan, hostScans.length ? hostScans : [scan]) : [];
  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle>
        {scan ? <Stack direction="row" spacing={1} alignItems="center">
          <span>{scan.hostname || scan.target}</span>
          <PathChip path={scan.path} />
          <StatusChip scan={scan} />
          <Typography variant="body2" color="text.secondary"><code>{scan.target}</code></Typography>
        </Stack> : "Network scan"}
      </DialogTitle>
      <DialogContent>
        {isLoading && <CircularProgress size={20} />}
        {scan && (
          <>
            <Typography variant="caption" color="text.secondary">
              Scanned {formatDateTime(scan.finishedAt ?? scan.createdAt)}
              {scan.durationSec ? ` in ${Math.round(scan.durationSec)}s` : ""}
              {scan.templatesVersion ? ` · templates ${scan.templatesVersion}` : ""}
              {scan.rangeName ? ` · range ${scan.rangeName}` : ""}
              {scan.scheduled ? " · scheduled" : ` · by ${scan.requester}`}
            </Typography>
            {scan.status === "unreachable" && (
              <Alert severity="warning" sx={{ mt: 1 }}>
                <strong>Not assessed.</strong> {scan.reason} Nothing below means this address is clean.
              </Alert>
            )}
            {scan.status === "failed" && <Alert severity="error" sx={{ mt: 1 }}>{scan.error}</Alert>}
            {(scan.warnings ?? []).map((w) => <Alert key={w} severity="info" sx={{ mt: 1 }}>{w}</Alert>)}

            {scan.status === "completed" && (
              <>
                <Typography variant="subtitle2" sx={{ mt: 2, mb: 0.5 }}>
                  Findings ({(scan.findings ?? []).length})
                </Typography>
                <Paper variant="outlined" sx={{ overflowX: "auto" }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell padding="checkbox" /><TableCell>Severity</TableCell><TableCell>Finding</TableCell>
                        <TableCell>Port</TableCell><TableCell>CVE</TableCell><TableCell align="right">CVSS</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(scan.findings ?? []).map((f) => <FindingRow key={f.id} f={f} />)}
                      {(scan.findings ?? []).length === 0 && (
                        <TableRow><TableCell colSpan={6}>
                          <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                            No vulnerabilities or misconfigurations found on the {scan.openPorts} open port{scan.openPorts === 1 ? "" : "s"}.
                          </Typography>
                        </TableCell></TableRow>
                      )}
                    </TableBody>
                  </Table>
                </Paper>

                <Typography variant="subtitle2" sx={{ mt: 2, mb: 0.5 }}>Services ({(scan.services ?? []).length})</Typography>
                <Paper variant="outlined" sx={{ overflowX: "auto" }}>
                  <Table size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell>Port</TableCell><TableCell>Service</TableCell><TableCell>Product / version</TableCell>
                        <TableCell>Process</TableCell><TableCell>Detected</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {(scan.services ?? []).map((s) => (
                        <TableRow key={`${s.proto}-${s.port}`}>
                          <TableCell><code>{s.port}/{s.proto}</code></TableCell>
                          <TableCell>
                            <Stack direction="row" spacing={0.5}>
                              <span>{s.service || "—"}</span>
                              {s.tls && <Chip size="small" variant="outlined" label="TLS" />}
                            </Stack>
                          </TableCell>
                          <TableCell><Typography variant="body2" sx={{ fontFamily: "monospace" }}>{productLabel(s)}</Typography></TableCell>
                          <TableCell>
                            {s.unexpected
                              ? <Tooltip title="No socket on the host is bound to this port."><Chip size="small" color="warning" label="unexpected" /></Tooltip>
                              : s.process || (scan.listenersKnown ? "—" : <Typography variant="caption" color="text.secondary">unknown</Typography>)}
                          </TableCell>
                          <TableCell>
                            <Typography variant="caption">{(s.detections ?? []).map((d) => d.name).join(", ") || "—"}</Typography>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </Paper>
              </>
            )}

            {scan.listenersKnown && quiet.length > 0 && (
              <>
                <Typography variant="subtitle2" sx={{ mt: 2, mb: 0.5 }}>
                  Listening but not reachable ({quiet.length})
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  Bound to a non-loopback address on the host, but no scan path reached them — the firewall doing its
                  job. Listed so that absence from the exposure list is not read as "not listening".
                </Typography>
                <Stack direction="row" spacing={0.5} flexWrap="wrap" sx={{ mt: 0.5 }}>
                  {quiet.map((l) => (
                    <Chip key={`${l.proto}/${l.port}`} size="small" variant="outlined"
                      label={`${l.port}/${l.proto}${l.process ? ` ${l.process}` : ""}`} />
                  ))}
                </Stack>
              </>
            )}
          </>
        )}
      </DialogContent>
      <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
    </Dialog>
  );
}
