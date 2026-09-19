import { useState } from "react";
import { PickList } from "../components/PickList";
import {
  Alert, Box, Button, Chip, CircularProgress, IconButton, MenuItem, Paper, Stack,
  Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import RefreshIcon from "@mui/icons-material/Refresh";
import { useQuery } from "@tanstack/react-query";
import {
  searchLogs, logHosts, logStatus, openLogConsole,
  type LogEntry, type LogQuery,
} from "../api/logs";

// LogsPage: the whole fleet's logs, in the place you already are.
//
// Deliberately not a second Dashboards. This answers the question an operator
// actually arrives with -- "what was this machine saying, around then" -- with
// the host list joined to what Provenance already knows and every search
// recorded against the person who ran it. The analysis that needs
// visualisations, alerting rules and Security Analytics is one click away in
// the embedded console, which is better at it than a table would be.

const RANGES: Array<{ value: string; label: string }> = [
  { value: "now-15m", label: "Last 15 minutes" },
  { value: "now-1h", label: "Last hour" },
  { value: "now-6h", label: "Last 6 hours" },
  { value: "now-24h", label: "Last 24 hours" },
  { value: "now-7d", label: "Last 7 days" },
  { value: "now-30d", label: "Last 30 days" },
];

// Severity as a NUMBER, because "warning or worse" is a range and an operator
// should not have to name every level they meant.
const SEVERITIES: Array<{ value: number; label: string }> = [
  { value: 0, label: "Any severity" },
  { value: 3, label: "Error or worse" },
  { value: 4, label: "Warning or worse" },
  { value: 5, label: "Notice or worse" },
  { value: 6, label: "Info or worse" },
];

const SEV_COLOUR: Record<string, "error" | "warning" | "info" | "default"> = {
  emerg: "error", emergency: "error", alert: "error", crit: "error", critical: "error",
  err: "error", error: "error",
  warn: "warning", warning: "warning",
  notice: "info", info: "default", informational: "default", debug: "default",
};

function when(ts: string): string {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit",
    minute: "2-digit", second: "2-digit",
  });
}

export function LogsPage() {
  const [text, setText] = useState("");
  const [host, setHost] = useState("");
  const [minSeverity, setMinSeverity] = useState(0);
  const [since, setSince] = useState("now-1h");
  // Held separately from the inputs so typing does not fire a query per
  // keystroke against a search cluster.
  const [applied, setApplied] = useState<LogQuery>({ since: "now-1h", limit: 200 });
  const [opening, setOpening] = useState(false);
  const [consoleError, setConsoleError] = useState("");

  // The session is minted BEFORE the tab opens, and the tab is opened from the
  // click, so the browser does not treat it as a popup. Opening first and minting
  // afterwards would land the person on a 401 from nginx and look broken.
  const openConsole = async () => {
    setOpening(true);
    setConsoleError("");
    try {
      const c = await openLogConsole();
      // The shipped dashboard, not Dashboards' home screen — the server names it,
      // so the id is not duplicated here. Falls back to the console root for a
      // backend older than that field.
      window.open(c.consoleURL || `${c.consoleBase}/`, "_blank", "noopener,noreferrer");
    } catch (e) {
      setConsoleError(e instanceof Error ? e.message : "could not open the log console");
    } finally {
      setOpening(false);
    }
  };

  const status = useQuery({ queryKey: ["log-status"], queryFn: logStatus, retry: false });
  const hosts = useQuery({
    queryKey: ["log-hosts"],
    queryFn: () => logHosts("now-7d"),
    enabled: status.data?.configured === true,
    retry: false,
  });
  const results = useQuery({
    queryKey: ["log-search", applied],
    queryFn: () => searchLogs(applied),
    enabled: status.data?.configured === true,
    retry: false,
  });

  const run = () =>
    setApplied({
      q: text.trim() || undefined,
      host: host || undefined,
      minSeverity: minSeverity || undefined,
      since,
      limit: 200,
    });

  const err = (results.error as { response?: { data?: { error?: string } } })?.response?.data?.error;

  // No collector is an ordinary deployment, not a fault — so say what to do
  // rather than showing an empty table and letting the operator guess.
  if (status.data && !status.data.configured) {
    return (
      <Box>
        <Typography variant="h5" sx={{ mb: 1 }}>Logs</Typography>
        <Alert severity="info">
          No log collector is configured. Point Provenance at an Aldgate collector by
          setting <code>PROV_ALDGATE_URL</code> (and <code>PROV_ALDGATE_USER</code> /
          <code> PROV_ALDGATE_PASSWORD</code>), then restart the backend.
          {status.data.hint ? <Box sx={{ mt: 1 }}>{status.data.hint}</Box> : null}
        </Alert>
      </Box>
    );
  }

  return (
    <Box>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Box>
          <Typography variant="h5">Logs</Typography>
          <Typography variant="body2" color="text.secondary">
            Everything the fleet has sent, searched through Provenance — the collector's
            credential stays on the server and every search is recorded against you.
          </Typography>
        </Box>
        <Stack direction="row" spacing={1}>
          <Tooltip title="Refresh">
            <IconButton aria-label="Refresh results" onClick={() => results.refetch()}>
              <RefreshIcon />
            </IconButton>
          </Tooltip>
          {/* The deep-analysis surface, deliberately not reimplemented here.
              It signs itself in: openLogConsole mints a scoped console session and
              the server swaps that for the collector credential this person's role
              earns, so nobody is asked for the password the console's own login
              form would otherwise demand. */}
          <Button startIcon={<OpenInNewIcon />} onClick={openConsole} disabled={opening}
            title="Open the full log console (OpenSearch Dashboards) for visualisations, alerting and Security Analytics">
            {opening ? "Opening…" : "Open log console"}
          </Button>
        </Stack>
      </Stack>

      <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
        <Stack direction={{ xs: "column", md: "row" }} spacing={2} alignItems="flex-start">
          <TextField label="Search messages" value={text} fullWidth size="small"
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") run(); }}
            helperText="All words must appear. Leave empty to see everything in the range." />
          {/* Typeable: nineteen hosts is already too many to hunt through a menu,
              and the count stays in the label so "which of these is noisy" is still
              answerable at a glance. */}
          <PickList label="Host" value={host} onChange={setHost} anyLabel="All hosts"
            sx={{ minWidth: 220 }}
            options={(hosts.data ?? []).map((h) => ({
              value: h.key, label: `${h.key} (${h.count})`,
            }))} />
          <TextField select label="Severity" value={minSeverity} size="small" sx={{ minWidth: 190 }}
            onChange={(e) => setMinSeverity(Number(e.target.value))}>
            {SEVERITIES.map((s) => <MenuItem key={s.value} value={s.value}>{s.label}</MenuItem>)}
          </TextField>
          <TextField select label="Time range" value={since} size="small" sx={{ minWidth: 180 }}
            onChange={(e) => setSince(e.target.value)}>
            {RANGES.map((r) => <MenuItem key={r.value} value={r.value}>{r.label}</MenuItem>)}
          </TextField>
          <Button variant="contained" startIcon={<SearchIcon />} onClick={run}
            disabled={results.isFetching} sx={{ mt: { md: 0.5 } }}>
            {results.isFetching ? "Searching…" : "Search"}
          </Button>
        </Stack>
      </Paper>

      {status.data?.reachable === false && (
        <Alert severity="error" sx={{ mb: 2 }}>
          The collector at <code>{status.data.url}</code> is not reachable: {status.data.error}
        </Alert>
      )}
      {results.isError && <Alert severity="error" sx={{ mb: 2 }}>{err || "The search failed."}</Alert>}
      {/* Shown here rather than in a toast: the usual cause is a collector whose
          console credentials have not been provisioned, and the fix is a sentence
          long. A button that quietly does nothing is the worst version of this. */}
      {consoleError ? (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setConsoleError("")}>
          {consoleError}
        </Alert>
      ) : null}

      {/* ?? [] on every list: the server now always sends arrays, but a page
          that unmounts itself because one field came back null is a blank
          screen with no error, and no amount of server-side care is worth
          betting a whole page on. */}
      {results.data && (
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 1.5 }}>
          <Chip size="small" label={`${results.data.total.toLocaleString()} matched`} />
          <Chip size="small" variant="outlined" label={`${results.data.tookMs} ms`} />
          {/* Which hosts and severities the match is spread across: how an
              operator gets from "something is wrong" to "it is that machine". */}
          {(results.data.bySeverity ?? []).map((s) => (
            <Chip key={s.key} size="small" label={`${s.key}: ${s.count}`}
              color={SEV_COLOUR[s.key] ?? "default"}
              variant={SEV_COLOUR[s.key] === "default" ? "outlined" : "filled"} />
          ))}
          {(results.data.byHost ?? []).slice(0, 8).map((h) => (
            <Chip key={h.key} size="small" variant="outlined" label={`${h.key}: ${h.count}`}
              onClick={() => { setHost(h.key); setApplied((a) => ({ ...a, host: h.key })); }} />
          ))}
        </Stack>
      )}

      <Paper variant="outlined">
        {results.isLoading ? (
          <Stack alignItems="center" sx={{ py: 6 }} spacing={1.5}>
            <CircularProgress size={28} />
            <Typography variant="body2" color="text.secondary">Searching…</Typography>
          </Stack>
        ) : (
          <Table size="small" sx={{ "& td": { verticalAlign: "top" } }}>
            <TableHead>
              <TableRow>
                <TableCell sx={{ width: 170 }}>Time</TableCell>
                <TableCell sx={{ width: 130 }}>Host</TableCell>
                <TableCell sx={{ width: 150 }}>Program</TableCell>
                <TableCell sx={{ width: 110 }}>Severity</TableCell>
                <TableCell>Message</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {(results.data?.entries ?? []).map((e: LogEntry, i: number) => (
                <TableRow key={i} hover>
                  <TableCell sx={{ whiteSpace: "nowrap", fontFamily: "monospace", fontSize: 12 }}>
                    {when(e.timestamp)}
                  </TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{e.host || "—"}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{e.program || "—"}</TableCell>
                  <TableCell>
                    {e.severity ? (
                      <Chip size="small" label={e.severity} color={SEV_COLOUR[e.severity] ?? "default"}
                        variant={SEV_COLOUR[e.severity] === "default" ? "outlined" : "filled"} />
                    ) : "—"}
                  </TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 12, wordBreak: "break-word" }}>
                    {e.message}
                  </TableCell>
                </TableRow>
              ))}
              {!results.isLoading && (results.data?.entries ?? []).length === 0 && (
                <TableRow>
                  <TableCell colSpan={5}>
                    <Typography variant="body2" color="text.secondary" sx={{ py: 2 }}>
                      {status.data?.hostsSending === 0
                        ? "The collector is reachable but no host has sent anything yet. Enrol hosts with the Aldgate playbook."
                        : "Nothing matched. Widen the time range, or clear the filters."}
                    </Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </Paper>
    </Box>
  );
}
