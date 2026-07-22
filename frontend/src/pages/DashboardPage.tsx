import {
  Autocomplete, Box, Button, Card, CardActionArea, CardContent, Checkbox, Chip, Dialog,
  DialogActions, DialogContent, DialogTitle, Grid, IconButton, List, ListItem, ListItemText,
  Stack, TextField, Tooltip, Typography,
} from "@mui/material";
import DnsIcon from "@mui/icons-material/Dns";
import TerminalIcon from "@mui/icons-material/Terminal";
import FolderIcon from "@mui/icons-material/Folder";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import HistoryIcon from "@mui/icons-material/History";
import HowToRegIcon from "@mui/icons-material/HowToReg";
import WarningAmberIcon from "@mui/icons-material/WarningAmber";
import TuneIcon from "@mui/icons-material/Tune";
import { useState, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { getVersion } from "../api/client";
import { listHosts, type Host } from "../api/hosts";
import { listSessions } from "../api/sessions";
import { listApprovals, listMyApprovals } from "../api/approvals";
import { listAudit } from "../api/audit";
import { listInsights } from "../api/insights";
import { useFleetEvents } from "../api/events";
import { getPreference, setPreference, QUICK_CONNECT_PREF, type QuickConnectPref } from "../api/preferences";
import { useAuthStore } from "../store/auth";

const STATUS_COLOR: Record<string, "success" | "error" | "warning" | "default"> = {
  online: "success", offline: "error", unknown: "warning",
};
const SEVERITY_COLOR: Record<string, "error" | "warning" | "info" | "default"> = {
  critical: "error", warning: "warning", info: "info",
};
const rank = (h: Host) => (h.status?.status === "online" ? 0 : h.status?.status === "unknown" ? 1 : 2);
const ago = (iso?: string) => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
};

// Landing dashboard: an at-a-glance, actionable overview — fleet health, quick
// connect, what's happening, and what needs attention. Sections render only when
// the signed-in user has permission for that data.
export function DashboardPage() {
  const qc = useQueryClient();
  const navigate = useNavigate();
  const has = useAuthStore((s) => s.has);

  const { data: version } = useQuery({ queryKey: ["version"], queryFn: getVersion });

  const { data: hostsResp } = useQuery({
    queryKey: ["hosts"], queryFn: listHosts,
    enabled: has("Host.View"), retry: false, refetchInterval: 30000,
  });
  const hosts = hostsResp?.hosts ?? [];

  const { data: sessions = [] } = useQuery({
    queryKey: ["sessions"], queryFn: listSessions,
    enabled: has("Session.Replay"), retry: false, refetchInterval: 30000,
  });
  const activeSessions = sessions.filter((s) => s.status === "active");

  const canApprove = has("Approval.Decide");
  const { data: approvals = [] } = useQuery({
    queryKey: ["dash-approvals", canApprove],
    queryFn: () => (canApprove ? listApprovals("pending") : listMyApprovals("pending")),
    retry: false, refetchInterval: 30000,
  });

  const { data: audit = [] } = useQuery({
    queryKey: ["dash-audit"], queryFn: () => listAudit({ limit: 8 }),
    enabled: has("Audit.View"), retry: false, refetchInterval: 30000,
  });

  const { data: insights = [] } = useQuery({
    queryKey: ["dash-insights"], queryFn: listInsights,
    enabled: has("Host.View"), retry: false, refetchInterval: 60000,
  });

  useFleetEvents((e) => {
    if (e.type === "host.status") {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      void qc.invalidateQueries({ queryKey: ["dash-insights"] });
    }
    if (e.type?.startsWith("session")) void qc.invalidateQueries({ queryKey: ["sessions"] });
  });

  const online = hosts.filter((h) => h.status?.status === "online").length;

  // Quick Connect is customizable: if the user has pinned specific hosts they show in
  // the chosen order; otherwise fall back to an auto-ranked top 6 (online first).
  const { data: quickPref } = useQuery({
    queryKey: ["pref", QUICK_CONNECT_PREF],
    queryFn: () => getPreference<QuickConnectPref>(QUICK_CONNECT_PREF),
    enabled: has("Host.View"), retry: false,
  });
  const [customizing, setCustomizing] = useState(false);
  const pinnedIds = quickPref?.hostIds ?? null;
  const autoQuick = [...hosts].sort((a, b) => rank(a) - rank(b) || a.hostname.localeCompare(b.hostname)).slice(0, 6);
  const quick = pinnedIds
    ? pinnedIds.map((id) => hosts.find((h) => h.id === id)).filter((h): h is Host => Boolean(h))
    : autoQuick;

  const openTerminal = (id: string) => window.open(`/terminals/${id}`, "_blank", "noopener");

  const stats: Array<{ label: string; value: number; sub?: string; icon: ReactNode; to: string; warn?: boolean }> = [];
  if (has("Host.View")) {
    stats.push({ label: "Hosts", value: hosts.length, sub: `${online} online`, icon: <DnsIcon />, to: "/hosts" });
  }
  if (has("Session.Replay")) {
    stats.push({ label: "Active sessions", value: activeSessions.length, icon: <HistoryIcon />, to: "/sessions" });
  }
  stats.push({
    label: canApprove ? "Pending approvals" : "My open requests",
    value: approvals.length, icon: <HowToRegIcon />, to: "/approvals",
    warn: approvals.length > 0,
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Overview</Typography>
        {version?.environment && (
          <Chip
            size="small" variant="outlined"
            label={version.environment}
            color={version.environment === "production" ? "success" : "warning"}
          />
        )}
      </Stack>

      <Grid container spacing={2} sx={{ mb: 1 }}>
        {stats.map((s) => (
          <Grid item xs={12} sm={6} md={3} key={s.label}>
            <Card variant="outlined">
              <CardActionArea onClick={() => navigate(s.to)}>
                <CardContent>
                  <Stack direction="row" alignItems="center" spacing={1} sx={{ color: "text.secondary", mb: 0.5 }}>
                    {s.icon}
                    <Typography variant="overline">{s.label}</Typography>
                  </Stack>
                  <Stack direction="row" alignItems="baseline" spacing={1}>
                    <Typography variant="h4" color={s.warn ? "warning.main" : "text.primary"}>{s.value}</Typography>
                    {s.sub && <Typography variant="body2" color="text.secondary">{s.sub}</Typography>}
                  </Stack>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={2}>
        {has("Host.View") && (
          <Grid item xs={12} md={7}>
            <Card variant="outlined">
              <CardContent sx={{ pb: 0 }}>
                <Stack direction="row" alignItems="center" spacing={0.5}>
                  <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 600 }}>Quick connect</Typography>
                  {pinnedIds && <Chip size="small" variant="outlined" label="custom" sx={{ mr: 0.5 }} />}
                  <Tooltip title="Customize which hosts appear here">
                    <IconButton size="small" onClick={() => setCustomizing(true)}><TuneIcon fontSize="small" /></IconButton>
                  </Tooltip>
                  <Button size="small" onClick={() => navigate("/terminals")}>All hosts</Button>
                </Stack>
              </CardContent>
              <List dense>
                {quick.map((h) => (
                  <ListItem
                    key={h.id}
                    secondaryAction={
                      <Stack direction="row" spacing={0.5}>
                        {h.protocol === "rdp" ? (
                          <Button size="small" variant="contained" startIcon={<DesktopWindowsIcon />} onClick={() => window.open(`/desktop/${h.id}`, "_blank", "noopener")}>Desktop</Button>
                        ) : (
                          <>
                            <Button size="small" variant="contained" startIcon={<TerminalIcon />} onClick={() => openTerminal(h.id)}>Terminal</Button>
                            <Button size="small" startIcon={<FolderIcon />} onClick={() => window.open(`/files/${h.id}`, "_blank", "noopener")}>Files</Button>
                          </>
                        )}
                      </Stack>
                    }
                  >
                    <Chip size="small" sx={{ mr: 1 }} label={h.status?.status ?? "unknown"} color={STATUS_COLOR[h.status?.status ?? "unknown"] ?? "default"} />
                    <ListItemText primary={h.hostname} secondary={[h.environment, h.address].filter(Boolean).join(" · ")} />
                  </ListItem>
                ))}
                {quick.length === 0 && (
                  pinnedIds ? (
                    <ListItem><ListItemText primary="Your pinned hosts aren't available."
                      secondary="They may have been removed or you lost access. Click the tune icon to update your Quick Connect list." /></ListItem>
                  ) : (
                    <ListItem><ListItemText primary="No hosts you can reach yet." secondary="Ask an admin for group or direct access, or request it under Approvals." /></ListItem>
                  )
                )}
              </List>
            </Card>
          </Grid>
        )}

        <Grid item xs={12} md={has("Host.View") ? 5 : 12}>
          <Stack spacing={2}>
            {has("Session.Replay") && (
              <Card variant="outlined">
                <CardContent sx={{ pb: 0 }}>
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <Box sx={{ width: 8, height: 8, borderRadius: "50%", bgcolor: activeSessions.length ? "success.main" : "text.disabled" }} />
                    <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 600 }}>
                      Live sessions ({activeSessions.length})
                    </Typography>
                    <Button size="small" onClick={() => navigate("/sessions")}>All</Button>
                  </Stack>
                </CardContent>
                <List dense>
                  {activeSessions.map((s) => (
                    <ListItem key={s.id}>
                      <ListItemText
                        primary={<><b>{s.username}</b>{"  →  "}{s.hostname}</>}
                        secondary={`connected ${ago(s.startedAt)}${s.clientIp ? "  ·  from " + s.clientIp : ""}`}
                      />
                    </ListItem>
                  ))}
                  {activeSessions.length === 0 && (
                    <ListItem><ListItemText primary="No one is connected right now." /></ListItem>
                  )}
                </List>
              </Card>
            )}

            {has("Audit.View") && (
              <Card variant="outlined">
                <CardContent sx={{ pb: 0 }}>
                  <Stack direction="row" alignItems="center">
                    <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 600 }}>Recent activity</Typography>
                    <Button size="small" onClick={() => navigate("/audit")}>Audit log</Button>
                  </Stack>
                </CardContent>
                <List dense>
                  {audit.map((e) => (
                    <ListItem key={e.id}>
                      <ListItemText
                        primary={`${e.action}${e.targetKind ? "  ·  " + e.targetKind : ""}`}
                        secondary={`${e.actorName ?? "system"}${e.ip ? "  ·  " + e.ip : ""}  ·  ${ago(e.createdAt)}`}
                      />
                    </ListItem>
                  ))}
                  {audit.length === 0 && <ListItem><ListItemText primary="No recent activity." /></ListItem>}
                </List>
              </Card>
            )}

            {has("Host.View") && insights.length > 0 && (
              <Card variant="outlined">
                <CardContent sx={{ pb: 1 }}>
                  <Stack direction="row" alignItems="center" spacing={1}>
                    <WarningAmberIcon color={insights.some((i) => i.severity === "critical") ? "error" : "warning"} />
                    <Typography variant="subtitle1" sx={{ flexGrow: 1, fontWeight: 600 }}>Needs attention</Typography>
                    <Button size="small" onClick={() => navigate("/hosts")}>Hosts</Button>
                  </Stack>
                </CardContent>
                <List dense>
                  {insights.slice(0, 8).map((i, idx) => (
                    <ListItem key={`${i.hostId}-${i.category}-${idx}`}>
                      <Chip
                        size="small" sx={{ mr: 1 }} label={i.severity}
                        color={SEVERITY_COLOR[i.severity] ?? "default"}
                      />
                      <ListItemText primary={`${i.hostname} — ${i.title}`} secondary={i.detail} />
                    </ListItem>
                  ))}
                </List>
              </Card>
            )}
          </Stack>
        </Grid>
      </Grid>

      {customizing && (
        <QuickConnectDialog
          hosts={hosts}
          pinnedIds={pinnedIds}
          onClose={() => setCustomizing(false)}
          onSaved={() => { setCustomizing(false); void qc.invalidateQueries({ queryKey: ["pref", QUICK_CONNECT_PREF] }); }}
        />
      )}
    </Box>
  );
}

// QuickConnectDialog lets a user choose exactly which hosts (and in what order) appear
// in Quick Connect. Saving an empty list clears the customization and restores the
// automatic top-6.
function QuickConnectDialog({ hosts, pinnedIds, onClose, onSaved }: {
  hosts: Host[]; pinnedIds: string[] | null; onClose: () => void; onSaved: () => void;
}) {
  const byId = new Map(hosts.map((h) => [h.id, h]));
  const initial = (pinnedIds ?? []).map((id) => byId.get(id)).filter((h): h is Host => Boolean(h));
  const [selected, setSelected] = useState<Host[]>(initial);
  const save = useMutation({
    mutationFn: () => setPreference<QuickConnectPref>(QUICK_CONNECT_PREF, { hostIds: selected.map((h) => h.id) }),
    onSuccess: onSaved,
  });
  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Customize Quick Connect</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Pick the hosts you want on your dashboard, in the order you want them. Leave it empty to
          restore the automatic list (online hosts first). This preference follows your account.
        </Typography>
        <Autocomplete
          multiple
          options={hosts}
          value={selected}
          onChange={(_, v) => setSelected(v)}
          getOptionLabel={(h) => h.hostname}
          isOptionEqualToValue={(a, b) => a.id === b.id}
          disableCloseOnSelect
          renderOption={(props, option, { selected: sel }) => (
            <li {...props} key={option.id}>
              <Checkbox size="small" checked={sel} sx={{ mr: 1 }} />
              <Box>
                <Typography variant="body2">{option.hostname}</Typography>
                <Typography variant="caption" color="text.secondary">
                  {[option.environment, option.address].filter(Boolean).join(" · ")}
                </Typography>
              </Box>
            </li>
          )}
          renderInput={(params) => <TextField {...params} label="Hosts" placeholder="Add a host…" />}
        />
      </DialogContent>
      <DialogActions>
        <Button color="inherit" onClick={() => setSelected([])} disabled={selected.length === 0}>Clear</Button>
        <Box sx={{ flexGrow: 1 }} />
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending} onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}
