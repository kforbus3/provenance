import { useEffect, useMemo, useState } from "react";
import { formatDateTime } from "../lib/datetime";
import {
  Autocomplete, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, Menu, Stack, TextField, Tooltip, Typography,
} from "@mui/material";
import {
  DataGrid, GridToolbarContainer, GridToolbarQuickFilter,
  type GridColDef, type GridRowSelectionModel,
} from "@mui/x-data-grid";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import EditIcon from "@mui/icons-material/Edit";
import RefreshIcon from "@mui/icons-material/Refresh";
import CableIcon from "@mui/icons-material/Cable";
import TerminalIcon from "@mui/icons-material/Terminal";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import FolderIcon from "@mui/icons-material/Folder";
import LockPersonIcon from "@mui/icons-material/LockPerson";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import InfoOutlinedIcon from "@mui/icons-material/InfoOutlined";
import HealthAndSafetyIcon from "@mui/icons-material/HealthAndSafety";
import MedicalServicesIcon from "@mui/icons-material/MedicalServices";
import { Alert, CircularProgress, List, ListItem, ListItemText, Paper, Snackbar } from "@mui/material";
import { MenuItem, ListItemSecondaryAction, Divider } from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  addHostGroup, addHostUser, createHost, deleteHost, enrollHost, finishEnroll,
  getHost, getHostAccess, listHosts, listHostSoftware, nextWGAddress, refreshHostFacts,
  removeHostGroup, removeHostUser, updateHost, setHostMaintenance, clearHostMaintenance, maintenanceActive,
  bulkRefreshHosts, bulkHostMaintenance, bulkHostTags,
} from "../api/hosts";
import { listVaultSecrets } from "../api/vault";
import {
  type EnrollmentResult, type EnrollParams, type Host, type HostInput,
} from "../api/hosts";
import { listGroups, listUsers } from "../api/admin";
import {
  listScanProfiles, listHostScans, startScan, prepareScan, scanReportUrl, fetchScanReport,
  listFindings, previewRemediation, remediate, remediationStatus,
  type HostScan, type ScanFinding,
} from "../api/scans";
import { downloadSupportBundle } from "../api/support";
import { triggerVulnScan } from "../api/vulnscan";
import { useAuthStore } from "../store/auth";
import {
  Checkbox, FormControl, FormControlLabel, FormLabel, Radio, RadioGroup,
} from "@mui/material";
import { WgDownChip, WgOnChip, wgDegraded, wgHealthy } from "../components/WgStatus";

const STATUS_COLOR: Record<string, "success" | "error" | "warning" | "default"> = {
  online: "success",
  offline: "error",
  unknown: "warning",
};

const EMPTY_FORM: HostInput = {
  hostname: "", description: "", environment: "", owner: "",
  address: "", wgAddress: "", sshPort: 22, sshUser: "", tags: [],
  authMethod: "fleet_cert", credentialId: null,
  protocol: "ssh", rdpPort: 3389, rdpOptions: {},
};

const fmtDate = (value?: string): string => formatDateTime(value);

// SupportBundleButton downloads a host's diagnostics+logs .tar.gz. Generation
// runs over SSH and takes a few seconds, so it shows a spinner and surfaces
// errors in a snackbar.
function SupportBundleButton({ host }: { host: Host }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const onClick = async () => {
    setLoading(true);
    setError(null);
    try {
      await downloadSupportBundle(host.id, host.hostname);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  return (
    <>
      <Tooltip title="Download support bundle (diagnostics + logs)">
        <span>
          <IconButton size="small" onClick={onClick} disabled={loading}>
            {loading ? <CircularProgress size={16} /> : <MedicalServicesIcon fontSize="small" />}
          </IconButton>
        </span>
      </Tooltip>
      <Snackbar open={!!error} autoHideDuration={6000} onClose={() => setError(null)}>
        <Alert severity="error" onClose={() => setError(null)}>{error}</Alert>
      </Snackbar>
    </>
  );
}

// Toolbar combines quick search with the New Host action and a bulk-delete
// button that appears only while rows are selected.
type BulkAction = "scan" | "refresh" | "maintenance" | "tags";

interface ToolbarProps {
  selectedCount: number;
  onNew: () => void;
  onDelete: () => void;
  onRefresh: () => void;
  onBulk: (action: BulkAction) => void;
}

// Teach the DataGrid slotProps about our custom toolbar's extra props.
declare module "@mui/x-data-grid" {
  interface ToolbarPropsOverrides extends ToolbarProps {}
}

function HostsToolbar({ selectedCount, onNew, onDelete, onRefresh, onBulk }: ToolbarProps) {
  const [bulkEl, setBulkEl] = useState<null | HTMLElement>(null);
  const pick = (a: BulkAction) => { setBulkEl(null); onBulk(a); };
  return (
    <GridToolbarContainer sx={{ p: 1, gap: 1 }}>
      <GridToolbarQuickFilter />
      <Box sx={{ flexGrow: 1 }} />
      {selectedCount > 0 && (
        <>
          <Button size="small" variant="outlined" onClick={(e) => setBulkEl(e.currentTarget)}>
            Bulk actions ({selectedCount})
          </Button>
          <Menu anchorEl={bulkEl} open={Boolean(bulkEl)} onClose={() => setBulkEl(null)}>
            <MenuItem onClick={() => pick("scan")}>Run vulnerability scan</MenuItem>
            <MenuItem onClick={() => pick("refresh")}>Refresh facts</MenuItem>
            <MenuItem onClick={() => pick("maintenance")}>Maintenance…</MenuItem>
            <MenuItem onClick={() => pick("tags")}>Edit tags…</MenuItem>
          </Menu>
          <Button
            color="error"
            size="small"
            startIcon={<DeleteIcon />}
            onClick={onDelete}
          >
            Delete ({selectedCount})
          </Button>
        </>
      )}
      <Tooltip title="Refresh">
        <IconButton size="small" onClick={onRefresh}>
          <RefreshIcon fontSize="small" />
        </IconButton>
      </Tooltip>
      <Button size="small" variant="contained" startIcon={<AddIcon />} onClick={onNew}>
        New Host
      </Button>
    </GridToolbarContainer>
  );
}

// hostToForm maps an existing host onto the editable form payload.
const hostToForm = (h: Host): HostInput => ({
  hostname: h.hostname, description: h.description ?? "", environment: h.environment ?? "",
  owner: h.owner ?? "", address: h.address ?? "", wgAddress: h.wgAddress ?? "",
  sshPort: h.sshPort || 22, sshUser: h.sshUser ?? "", tags: h.tags ?? [],
  authMethod: h.authMethod ?? "fleet_cert", credentialId: h.credentialId ?? null,
  protocol: h.protocol ?? "ssh", rdpPort: h.rdpPort || 3389, rdpOptions: h.rdpOptions ?? {},
});

// NewHostDialog collects the create/edit payload; tags are entered as a
// comma-separated list and normalized on submit. When `editHost` is set it edits
// that host in place (e.g. to set a management Address) rather than creating one.
interface NewHostDialogProps {
  open: boolean;
  editHost?: Host | null;
  onClose: () => void;
  onSubmit: (input: HostInput) => void;
  submitting: boolean;
}

function NewHostDialog({ open, editHost, onClose, onSubmit, submitting }: NewHostDialogProps) {
  const isEdit = Boolean(editHost);
  const [form, setForm] = useState<HostInput>(EMPTY_FORM);
  const [tags, setTags] = useState("");
  const { data: vaultSecrets = [] } = useQuery({ queryKey: ["vault-secrets"], queryFn: listVaultSecrets, enabled: open });

  // Prefill from the host when editing; reset to blank when creating.
  useEffect(() => {
    if (!open) return;
    if (editHost) {
      setForm(hostToForm(editHost));
      setTags((editHost.tags ?? []).join(", "));
    } else {
      setForm(EMPTY_FORM);
      setTags("");
    }
  }, [open, editHost]);

  // Show what auto-assignment would pick from the overlay pool.
  const { data: nextWG } = useQuery({
    queryKey: ["next-wg"],
    queryFn: nextWGAddress,
    enabled: open && !isEdit,
  });

  const set = (key: keyof HostInput) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [key]: e.target.value }));

  const handleSubmit = () => {
    onSubmit({
      ...form,
      sshPort: Number(form.sshPort) || 22,
      rdpPort: Number(form.rdpPort) || 3389,
      tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
    });
  };

  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{isEdit ? `Edit ${editHost?.hostname}` : "New Host"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField
            label="Hostname" required value={form.hostname}
            onChange={set("hostname")} autoFocus fullWidth
          />
          <TextField label="Description" value={form.description} onChange={set("description")} fullWidth />
          <Stack direction="row" spacing={2}>
            <TextField label="Environment" value={form.environment} onChange={set("environment")} fullWidth />
            <TextField label="Owner" value={form.owner} onChange={set("owner")} fullWidth />
          </Stack>
          <Stack direction="row" spacing={2}>
            <TextField
              label="Address" value={form.address} onChange={set("address")} fullWidth
              helperText="Management address used to reach the host. Leave blank to auto-show the monitored primary IP."
            />
            <TextField
              label="WireGuard Address" value={form.wgAddress} onChange={set("wgAddress")} fullWidth
              placeholder={nextWG?.nextWgAddress ? `auto: ${nextWG.nextWgAddress}` : "auto-assign"}
              helperText={
                nextWG?.exhausted
                  ? `Overlay pool ${nextWG.subnet} exhausted`
                  : nextWG?.nextWgAddress
                    ? `Leave blank to auto-assign ${nextWG.nextWgAddress} from ${nextWG.subnet}`
                    : "Leave blank to auto-assign from the overlay pool"
              }
            />
          </Stack>
          <Stack direction="row" spacing={2}>
            <TextField
              label="SSH Port" type="number" value={form.sshPort}
              onChange={set("sshPort")} sx={{ width: 140 }}
            />
            <TextField label="SSH User" value={form.sshUser} onChange={set("sshUser")} fullWidth />
          </Stack>
          <TextField
            label="Tags" helperText="Comma-separated" value={tags}
            onChange={(e) => setTags(e.target.value)} fullWidth
          />
          <Stack direction="row" spacing={2}>
            <TextField select label="Protocol" value={form.protocol ?? "ssh"} fullWidth
              helperText="How operators connect to this host"
              onChange={(e) => setForm((f) => ({
                ...f,
                protocol: e.target.value,
                // RDP requires a vaulted password credential.
                authMethod: e.target.value === "rdp" && (f.authMethod ?? "fleet_cert") === "fleet_cert"
                  ? "vault_password" : f.authMethod,
              }))}>
              <MenuItem value="ssh">SSH (terminal)</MenuItem>
              <MenuItem value="rdp">RDP (Windows desktop)</MenuItem>
            </TextField>
            {form.protocol === "rdp" && (
              <TextField
                label="RDP Port" type="number" value={form.rdpPort ?? 3389}
                onChange={set("rdpPort")} sx={{ width: 140 }}
              />
            )}
          </Stack>
          <TextField select label="Authentication" value={form.authMethod ?? "fleet_cert"} fullWidth
            helperText={form.protocol === "rdp"
              ? "RDP is brokered with a vaulted password credential — the operator never sees it"
              : "How Fleet authenticates to this host"}
            onChange={(e) => setForm((f) => ({ ...f, authMethod: e.target.value, credentialId: e.target.value === "fleet_cert" ? null : f.credentialId }))}>
            {form.protocol !== "rdp" && <MenuItem value="fleet_cert">Fleet certificate (default)</MenuItem>}
            <MenuItem value="vault_password">Vault credential — password</MenuItem>
            {form.protocol !== "rdp" && <MenuItem value="vault_ssh_key">Vault credential — SSH key</MenuItem>}
          </TextField>
          {form.authMethod && form.authMethod !== "fleet_cert" && (
            <TextField select label="Credential" value={form.credentialId ?? ""} fullWidth
              helperText="Injected at connect time — the operator never sees it"
              onChange={(e) => setForm((f) => ({ ...f, credentialId: e.target.value }))}>
              {vaultSecrets.length === 0 && <MenuItem value="" disabled>No accessible credentials — add one in Credentials</MenuItem>}
              {vaultSecrets.map((s) => (
                <MenuItem key={s.id} value={s.id}>
                  {(s.folder ? `${s.folder} / ` : "") + s.name}{s.username ? ` (${s.username})` : ""}
                </MenuItem>
              ))}
            </TextField>
          )}
          {form.protocol === "rdp" && (
            <>
              <Divider textAlign="left"><Typography variant="caption" color="text.secondary">Desktop display & security</Typography></Divider>
              <Stack direction="row" spacing={2}>
                <TextField select label="Security mode" fullWidth
                  value={form.rdpOptions?.security ?? "any"}
                  helperText="Match the host's RDP setting; NLA for locked-down Windows"
                  onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, security: e.target.value } }))}>
                  <MenuItem value="any">Any (negotiate)</MenuItem>
                  <MenuItem value="nla">NLA</MenuItem>
                  <MenuItem value="tls">TLS</MenuItem>
                  <MenuItem value="rdp">RDP (legacy)</MenuItem>
                  <MenuItem value="vmconnect">Hyper-V (vmconnect)</MenuItem>
                </TextField>
                <TextField select label="Color depth" sx={{ width: 160 }}
                  value={form.rdpOptions?.colorDepth ?? 0}
                  onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, colorDepth: Number(e.target.value) } }))}>
                  <MenuItem value={0}>Default</MenuItem>
                  <MenuItem value={8}>8-bit</MenuItem>
                  <MenuItem value={16}>16-bit</MenuItem>
                  <MenuItem value={24}>24-bit</MenuItem>
                  <MenuItem value={32}>32-bit</MenuItem>
                </TextField>
              </Stack>
              <Stack direction="row" spacing={2}>
                <TextField label="Width" type="number" sx={{ width: 120 }}
                  value={form.rdpOptions?.width ?? 0}
                  helperText="0 = fit window"
                  onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, width: Number(e.target.value) } }))} />
                <TextField label="Height" type="number" sx={{ width: 120 }}
                  value={form.rdpOptions?.height ?? 0}
                  helperText="0 = fit window"
                  onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, height: Number(e.target.value) } }))} />
                <TextField label="DPI" type="number" sx={{ width: 120 }}
                  value={form.rdpOptions?.dpi ?? 0}
                  helperText="0 = 96"
                  onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, dpi: Number(e.target.value) } }))} />
                <TextField label="Domain" fullWidth
                  value={form.rdpOptions?.domain ?? ""}
                  placeholder="AD domain (optional)"
                  onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, domain: e.target.value } }))} />
              </Stack>
              <Stack direction="row" spacing={2}>
                <FormControlLabel
                  control={<Checkbox checked={form.rdpOptions?.disableAudio ?? false}
                    onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, disableAudio: e.target.checked } }))} />}
                  label="Disable audio" />
                <FormControlLabel
                  control={<Checkbox checked={form.rdpOptions?.enableTheming ?? false}
                    onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, enableTheming: e.target.checked } }))} />}
                  label="Wallpaper & theming" />
              </Stack>
              <Divider textAlign="left"><Typography variant="caption" color="text.secondary">Clipboard (data transfer — off by default)</Typography></Divider>
              <Stack direction="row" spacing={2}>
                <FormControlLabel
                  control={<Checkbox checked={form.rdpOptions?.clipboardCopy ?? false}
                    onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, clipboardCopy: e.target.checked } }))} />}
                  label="Allow copy (desktop → browser)" />
                <FormControlLabel
                  control={<Checkbox checked={form.rdpOptions?.clipboardPaste ?? false}
                    onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, clipboardPaste: e.target.checked } }))} />}
                  label="Allow paste (browser → desktop)" />
              </Stack>
              <Divider textAlign="left"><Typography variant="caption" color="text.secondary">Drive redirection / file transfer (off by default)</Typography></Divider>
              <FormControlLabel
                control={<Checkbox checked={form.rdpOptions?.enableDrive ?? false}
                  onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, enableDrive: e.target.checked } }))} />}
                label="Enable drive (mounts a Fleet drive in the desktop)" />
              {form.rdpOptions?.enableDrive && (
                <Stack direction="row" spacing={2} sx={{ pl: 4 }}>
                  <FormControlLabel
                    control={<Checkbox checked={form.rdpOptions?.driveUpload ?? false}
                      onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, driveUpload: e.target.checked } }))} />}
                    label="Allow upload (browser → desktop)" />
                  <FormControlLabel
                    control={<Checkbox checked={form.rdpOptions?.driveDownload ?? false}
                      onChange={(e) => setForm((f) => ({ ...f, rdpOptions: { ...f.rdpOptions, driveDownload: e.target.checked } }))} />}
                    label="Allow download (desktop → browser)" />
                </Stack>
              )}
            </>
          )}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained" onClick={handleSubmit}
          disabled={submitting || form.hostname.trim() === ""}
        >
          {isEdit ? "Save" : "Create"}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// Host inventory grid: searchable, sortable, paginated, with multi-select bulk
// delete and a create dialog. Theme (light/dark) is inherited from the provider.
export function HostsPage() {
  const qc = useQueryClient();
  const { data, isLoading, refetch } = useQuery({
    queryKey: ["hosts"],
    queryFn: listHosts,
  });

  const [selection, setSelection] = useState<GridRowSelectionModel>([]);
  const [groupFilter, setGroupFilter] = useState<string[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [enrollResult, setEnrollResult] = useState<EnrollmentResult | null>(null);
  const [enrollError, setEnrollError] = useState<string | null>(null);
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [enrollTarget, setEnrollTarget] = useState<Host | null>(null);
  const [accessTarget, setAccessTarget] = useState<Host | null>(null);
  const [detailsTarget, setDetailsTarget] = useState<Host | null>(null);
  const [scanTarget, setScanTarget] = useState<Host | null>(null);
  const [editTarget, setEditTarget] = useState<Host | null>(null);
  const [bulkMsg, setBulkMsg] = useState<string | null>(null);
  const [bulkMaintOpen, setBulkMaintOpen] = useState(false);
  const [bulkTagsOpen, setBulkTagsOpen] = useState(false);

  const selectedIds = selection.map(String);
  const bulkScanMut = useMutation({
    mutationFn: () => triggerVulnScan({ hostIds: selectedIds }),
    onSuccess: (ids) => setBulkMsg(`Started ${ids.length} vulnerability scan(s)`),
    onError: () => setBulkMsg("Bulk scan failed"),
  });
  const bulkRefreshMut = useMutation({
    mutationFn: () => bulkRefreshHosts(selectedIds),
    onSuccess: (n) => setBulkMsg(`Queued a facts refresh on ${n} host(s)`),
    onError: () => setBulkMsg("Bulk refresh failed"),
  });
  const onBulk = (action: BulkAction) => {
    if (action === "scan") bulkScanMut.mutate();
    else if (action === "refresh") bulkRefreshMut.mutate();
    else if (action === "maintenance") setBulkMaintOpen(true);
    else if (action === "tags") setBulkTagsOpen(true);
  };

  const createMut = useMutation({
    mutationFn: createHost,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      setDialogOpen(false);
    },
  });

  const updateMut = useMutation({
    mutationFn: ({ id, input }: { id: string; input: HostInput }) => updateHost(id, input),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      setEditTarget(null);
    },
  });

  const enrollMut = useMutation({
    mutationFn: ({ id, params }: { id: string; params: EnrollParams }) => enrollHost(id, params),
    onMutate: () => {
      setEnrollTarget(null);
      setEnrollOpen(true);
      setEnrollResult(null);
      setEnrollError(null);
    },
    onSuccess: (res) => {
      setEnrollResult(res);
      void qc.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { error?: string } } };
      setEnrollError(e.response?.data?.error ?? "Enrollment failed.");
    },
  });

  // No-install (ssh-pipe) completion: reuses the enrollment result dialog.
  const finishMut = useMutation({
    mutationFn: ({ id, hostPublicKey }: { id: string; hostPublicKey: string }) => finishEnroll(id, hostPublicKey),
    onMutate: () => {
      setEnrollTarget(null);
      setEnrollOpen(true);
      setEnrollResult(null);
      setEnrollError(null);
    },
    onSuccess: (res) => {
      setEnrollResult(res);
      void qc.invalidateQueries({ queryKey: ["hosts"] });
    },
    onError: (err: unknown) => {
      const e = err as { response?: { data?: { error?: string } } };
      setEnrollError(e.response?.data?.error ?? "Finish failed.");
    },
  });

  const deleteMut = useMutation({
    mutationFn: async (ids: string[]) => {
      await Promise.all(ids.map((id) => deleteHost(id)));
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["hosts"] });
      setSelection([]);
    },
  });

  const columns = useMemo<GridColDef<Host>[]>(() => [
    { field: "hostname", headerName: "Hostname", minWidth: 160, flex: 1 },
    { field: "description", headerName: "Description", minWidth: 180, flex: 1 },
    { field: "environment", headerName: "Environment", minWidth: 130 },
    { field: "owner", headerName: "Owner", minWidth: 130 },
    {
      field: "address", headerName: "Address", minWidth: 160,
      // Fall back to the monitor-collected primary IP when no management address
      // is set, so a host enrolled by hostname still shows an IP. It refreshes on
      // each monitoring sweep, so it tracks DHCP changes; a user-set address wins.
      renderCell: (params) => {
        const explicit = params.row.address as string | undefined;
        if (explicit) return explicit;
        const auto = params.row.metrics?.primaryIp as string | undefined;
        return auto ? (
          <Tooltip title="Auto-detected from monitoring — the host's current primary IP (tracks DHCP)">
            <span style={{ opacity: 0.75 }}>{auto} <em style={{ fontSize: 11 }}>(auto)</em></span>
          </Tooltip>
        ) : "";
      },
    },
    {
      field: "wgAddress", headerName: "WG Address", minWidth: 160,
      renderCell: (params) => (
        <Stack direction="row" spacing={0.5} alignItems="center">
          <span>{params.row.wgAddress || "—"}</span>
          {wgDegraded(params.row) && <WgDownChip />}
          {wgHealthy(params.row) && <WgOnChip />}
        </Stack>
      ),
    },
    {
      field: "sshVersion", headerName: "SSH Version", minWidth: 130,
      valueGetter: (_v, row) => row.inventory?.sshVersion ?? "",
    },
    {
      field: "status", headerName: "Status", minWidth: 150, sortable: true,
      valueGetter: (_v, row) => row.status?.status ?? "unknown",
      renderCell: (params) => {
        const s = String(params.value ?? "unknown");
        return (
          <Stack direction="row" spacing={0.5} alignItems="center">
            <Chip size="small" label={s} color={STATUS_COLOR[s] ?? "default"} />
            {wgDegraded(params.row) && <WgDownChip />}
            {maintenanceActive(params.row) && (
              <Tooltip title="In maintenance — alerts silenced">
                <Chip size="small" label="maint" color="warning" variant="outlined" />
              </Tooltip>
            )}
          </Stack>
        );
      },
    },
    {
      field: "latency", headerName: "Latency", minWidth: 110, type: "number",
      valueGetter: (_v, row) => row.status?.latencyMs ?? null,
      valueFormatter: (value) => (value == null ? "—" : `${value} ms`),
    },
    {
      field: "tags", headerName: "Tags", minWidth: 180, flex: 1, sortable: false,
      valueGetter: (_v, row) => (row.tags ?? []).join(", "),
      renderCell: (params) => (
        <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", py: 0.5 }}>
          {(params.row.tags ?? []).map((t) => (
            <Chip key={t} size="small" label={t} variant="outlined" />
          ))}
        </Stack>
      ),
    },
    {
      field: "groups", headerName: "Groups", minWidth: 160, sortable: false,
      valueGetter: (_v, row) => (row.groups ?? []).join(", "),
      renderCell: (params) => (
        <Stack direction="row" spacing={0.5} sx={{ flexWrap: "wrap", py: 0.5 }}>
          {(params.row.groups ?? []).map((g) => (
            <Chip key={g} size="small" label={g} />
          ))}
        </Stack>
      ),
    },
    {
      field: "lastSeen", headerName: "Last Seen", minWidth: 180,
      valueGetter: (_v, row) => row.status?.checkedAt ?? "",
      valueFormatter: (value) => fmtDate(value ? String(value) : undefined),
    },
    {
      field: "actions", headerName: "Actions", width: 326, sortable: false, filterable: false,
      renderCell: (params) => (
        <Stack direction="row" spacing={0.5}>
          <Tooltip title="Host details">
            <IconButton size="small" onClick={() => setDetailsTarget(params.row)}>
              <InfoOutlinedIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          <Tooltip title="Edit host (address, SSH user/port, tags)">
            <IconButton size="small" onClick={() => setEditTarget(params.row)}>
              <EditIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          {/* Scan (OpenSCAP) and support bundle run over SSH — not applicable to RDP hosts. */}
          {params.row.protocol !== "rdp" && (
            <>
              <Tooltip title="Security scan (OpenSCAP)">
                <IconButton size="small" onClick={() => setScanTarget(params.row)}>
                  <HealthAndSafetyIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <SupportBundleButton host={params.row} />
            </>
          )}
          {params.row.protocol === "rdp" ? (
            <Tooltip title="Open Windows desktop (RDP) in a new tab">
              <IconButton
                size="small" color="primary"
                onClick={() => window.open(`/desktop/${params.row.id}`, "_blank", "noopener")}
              >
                <DesktopWindowsIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          ) : (
            <>
              <Tooltip title="Open terminal in a new tab">
                <IconButton
                  size="small" color="primary"
                  onClick={() => window.open(`/terminals/${params.row.id}`, "_blank", "noopener")}
                >
                  <TerminalIcon fontSize="small" />
                </IconButton>
              </Tooltip>
              <Tooltip title="Browse files (SFTP) in a new tab">
                <IconButton
                  size="small"
                  onClick={() => window.open(`/files/${params.row.id}`, "_blank", "noopener")}
                >
                  <FolderIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </>
          )}
          <Tooltip title="Manage access (groups & users)">
            <IconButton size="small" onClick={() => setAccessTarget(params.row)}>
              <LockPersonIcon fontSize="small" />
            </IconButton>
          </Tooltip>
          {/* SSH hosts enroll via a bash script; RDP (Windows) hosts via a PowerShell
              WireGuard script — both join the host to the overlay for remote reach. */}
          <Tooltip title={params.row.enrolled
            ? "Re-enroll (provision WireGuard)"
            : params.row.protocol === "rdp"
              ? "Enroll on the overlay (Windows / WireGuard)"
              : "Enroll (provision WireGuard)"}>
            <span>
              <IconButton
                size="small"
                color={params.row.enrolled ? "success" : "primary"}
                disabled={enrollMut.isPending}
                onClick={() => setEnrollTarget(params.row)}
              >
                <CableIcon fontSize="small" />
              </IconButton>
            </span>
          </Tooltip>
          <Tooltip title="Delete host">
            <IconButton
              size="small" color="error"
              onClick={() => deleteMut.mutate([params.row.id])}
            >
              <DeleteIcon fontSize="small" />
            </IconButton>
          </Tooltip>
        </Stack>
      ),
    },
  ], [deleteMut, enrollMut]);

  const allHosts = data?.hosts ?? [];
  const groupOptions = Array.from(new Set(allHosts.flatMap((h) => h.groups ?? []))).sort();
  const rows = groupFilter.length
    ? allHosts.filter((h) => (h.groups ?? []).some((g) => groupFilter.includes(g)))
    : allHosts;

  return (
    <Box>
      <Typography variant="h5" gutterBottom>
        Host Inventory
      </Typography>
      {groupOptions.length > 0 && (
        <Autocomplete
          multiple size="small" options={groupOptions} value={groupFilter}
          onChange={(_, v) => setGroupFilter(v)} sx={{ mb: 1.5, maxWidth: 480 }}
          renderInput={(params) => <TextField {...params} label="Filter by group" />}
        />
      )}
      <Box sx={{ width: "100%", height: "calc(100vh - 230px)" }}>
        <DataGrid<Host>
          rows={rows}
          columns={columns}
          loading={isLoading || deleteMut.isPending}
          getRowId={(row) => row.id}
          checkboxSelection
          disableRowSelectionOnClick
          rowSelectionModel={selection}
          onRowSelectionModelChange={setSelection}
          pageSizeOptions={[10, 25, 50, 100]}
          initialState={{
            pagination: { paginationModel: { pageSize: 25, page: 0 } },
            // Keep the default view simple: the essentials for finding a host and
            // connecting. The rest are one click away in the column menu.
            columns: {
              columnVisibilityModel: {
                owner: false, wgAddress: false, sshVersion: false,
                latency: false, groups: false,
              },
            },
          }}
          getRowHeight={() => "auto"}
          slots={{ toolbar: HostsToolbar }}
          slotProps={{
            toolbar: {
              selectedCount: selection.length,
              onNew: () => setDialogOpen(true),
              onDelete: () => deleteMut.mutate(selection.map(String)),
              onRefresh: () => void refetch(),
              onBulk,
            },
          }}
          sx={{ "& .MuiDataGrid-cell": { alignItems: "flex-start", py: 0.5 } }}
        />
      </Box>
      {/* key forces a fresh component (and fresh form state) on each open, so a
          previous host's typed values never bleed into the next. */}
      <NewHostDialog
        key={dialogOpen ? "new-open" : "new-closed"}
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        onSubmit={(input) => createMut.mutate(input)}
        submitting={createMut.isPending}
      />
      <NewHostDialog
        key={editTarget?.id ?? "edit-none"}
        open={Boolean(editTarget)}
        editHost={editTarget}
        onClose={() => setEditTarget(null)}
        onSubmit={(input) => editTarget && updateMut.mutate({ id: editTarget.id, input })}
        submitting={updateMut.isPending}
      />
      <EnrollCredsDialog
        key={enrollTarget?.id ?? "enroll-none"}
        host={enrollTarget}
        onClose={() => setEnrollTarget(null)}
        onSubmit={(params) => enrollTarget && enrollMut.mutate({ id: enrollTarget.id, params })}
        onPipeFinish={(hostPublicKey) => enrollTarget && finishMut.mutate({ id: enrollTarget.id, hostPublicKey })}
      />
      <EnrollDialog
        open={enrollOpen}
        pending={enrollMut.isPending || finishMut.isPending}
        result={enrollResult}
        error={enrollError}
        onClose={() => setEnrollOpen(false)}
      />
      <HostAccessDialog key={accessTarget?.id ?? "access-none"} host={accessTarget} onClose={() => setAccessTarget(null)} />

      <HostDetailsDialog key={detailsTarget?.id ?? "details-none"} host={detailsTarget} onClose={() => setDetailsTarget(null)} />

      <HostScanDialog key={scanTarget?.id ?? "scan-none"} host={scanTarget} onClose={() => setScanTarget(null)} />

      <BulkMaintenanceDialog
        open={bulkMaintOpen} count={selectedIds.length}
        onClose={() => setBulkMaintOpen(false)}
        onApply={async (minutes) => {
          try {
            const n = await bulkHostMaintenance(selectedIds, minutes);
            setBulkMsg(minutes > 0 ? `Put ${n} host(s) in maintenance` : `Cleared maintenance on ${n} host(s)`);
            void qc.invalidateQueries({ queryKey: ["hosts"] });
          } catch { setBulkMsg("Bulk maintenance failed"); }
          setBulkMaintOpen(false);
        }}
      />
      <BulkTagsDialog
        open={bulkTagsOpen} count={selectedIds.length}
        onClose={() => setBulkTagsOpen(false)}
        onApply={async (add, remove) => {
          try {
            const n = await bulkHostTags(selectedIds, { add, remove });
            setBulkMsg(`Updated tags on ${n} host(s)`);
            void qc.invalidateQueries({ queryKey: ["hosts"] });
          } catch { setBulkMsg("Bulk tag update failed"); }
          setBulkTagsOpen(false);
        }}
      />
      <Snackbar
        open={!!bulkMsg} autoHideDuration={4000} onClose={() => setBulkMsg(null)}
        anchorOrigin={{ vertical: "bottom", horizontal: "center" }}
      >
        <Alert severity="info" onClose={() => setBulkMsg(null)}>{bulkMsg}</Alert>
      </Snackbar>
    </Box>
  );
}

// BulkMaintenanceDialog silences (or clears) alerts on the selected hosts.
function BulkMaintenanceDialog({
  open, count, onClose, onApply,
}: { open: boolean; count: number; onClose: () => void; onApply: (minutes: number) => void }) {
  const [minutes, setMinutes] = useState(60);
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>Maintenance — {count} host(s)</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Silence offline / updates-pending / scan-failure alerts on the selected hosts while you
          patch or reboot them, or clear an active window.
        </Typography>
        <TextField
          select fullWidth size="small" label="Silence for" value={minutes}
          onChange={(e) => setMinutes(Number(e.target.value))}
        >
          <MenuItem value={60}>1 hour</MenuItem>
          <MenuItem value={240}>4 hours</MenuItem>
          <MenuItem value={480}>8 hours</MenuItem>
          <MenuItem value={1440}>24 hours</MenuItem>
        </TextField>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button color="warning" onClick={() => onApply(0)}>Clear maintenance</Button>
        <Button variant="contained" onClick={() => onApply(minutes)}>Silence</Button>
      </DialogActions>
    </Dialog>
  );
}

// BulkTagsDialog adds and/or removes tags across the selected hosts.
function BulkTagsDialog({
  open, count, onClose, onApply,
}: { open: boolean; count: number; onClose: () => void; onApply: (add: string[], remove: string[]) => void }) {
  const [add, setAdd] = useState("");
  const [remove, setRemove] = useState("");
  const parse = (s: string) => s.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
  const addTags = parse(add);
  const removeTags = parse(remove);
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>Edit tags — {count} host(s)</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <TextField
            label="Add tags" size="small" fullWidth value={add}
            onChange={(e) => setAdd(e.target.value)}
            helperText="Comma- or newline-separated"
          />
          <TextField
            label="Remove tags" size="small" fullWidth value={remove}
            onChange={(e) => setRemove(e.target.value)}
            helperText="Comma- or newline-separated"
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          disabled={addTags.length === 0 && removeTags.length === 0}
          onClick={() => onApply(addTags, removeTags)}
        >
          Apply
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function scanColor(s: string): "default" | "success" | "error" | "warning" | "info" {
  if (s === "completed") return "success";
  if (s === "failed") return "error";
  if (s === "running") return "info";
  return "warning";
}

// HostScanDialog runs OpenSCAP scans and lists their reports. Profiles are
// discovered from the host on open; scans run in the background (the list polls
// while any is active). Reports are viewed in a sandboxed iframe or downloaded.
function HostScanDialog({ host, onClose }: { host: Host | null; onClose: () => void }) {
  const qc = useQueryClient();
  const hostId = host?.id ?? "";
  const token = useAuthStore((s) => s.accessToken) ?? "";
  const canRemediate = useAuthStore((s) => s.has)("Host.Remediate");
  const [profile, setProfile] = useState("");
  const [skipExpensive, setSkipExpensive] = useState(false);
  const [skipRulesText, setSkipRulesText] = useState("");
  const [reportId, setReportId] = useState<string | null>(null);
  const [remediateScan, setRemediateScan] = useState<HostScan | null>(null);

  const { data: prof, isLoading: profLoading } = useQuery({
    queryKey: ["scan-profiles", hostId],
    queryFn: () => listScanProfiles(hostId),
    enabled: Boolean(host),
    retry: false,
    // Poll while the scanner is installing so profiles appear when it's ready.
    refetchInterval: (q) => ((q.state.data as { installing?: boolean } | undefined)?.installing ? 6000 : false),
  });

  const { data: scans = [] } = useQuery({
    queryKey: ["host-scans", hostId],
    queryFn: () => listHostScans(hostId),
    enabled: Boolean(host),
    refetchInterval: (q) => {
      const list = q.state.data as HostScan[] | undefined;
      return list?.some((s) => s.status === "pending" || s.status === "running") ? 4000 : false;
    },
  });

  // A completed scan also installs the scanner, so refresh the profile list then.
  const completedCount = scans.filter((s) => s.status === "completed").length;
  useEffect(() => {
    if (completedCount > 0) void qc.invalidateQueries({ queryKey: ["scan-profiles", hostId] });
  }, [completedCount, hostId, qc]);

  const prepareMut = useMutation({
    mutationFn: () => prepareScan(hostId),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["scan-profiles", hostId] }),
  });

  const runMut = useMutation({
    mutationFn: () => startScan(hostId, profile, {
      skipExpensiveFsRules: skipExpensive,
      skipRules: skipRulesText.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean),
    }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["host-scans", hostId] }),
  });

  return (
    <>
      <Dialog open={Boolean(host)} onClose={onClose} fullWidth maxWidth="md">
        <DialogTitle>Security scan · {host?.hostname}</DialogTitle>
        <DialogContent dividers>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Runs an OpenSCAP compliance scan over SSH and stores an HTML report. The scanner is
            installed automatically if missing, so the first scan on a host can take several minutes.
          </Typography>
          <Stack direction="row" spacing={2} alignItems="flex-start" sx={{ mb: 1 }}>
            <TextField
              select size="small" label="Profile" value={profile}
              onChange={(e) => setProfile(e.target.value)} sx={{ flexGrow: 1 }}
              helperText={profLoading ? "Loading profiles from host…" : prof ? `${prof.profiles.length} profiles available` : undefined}
            >
              <MenuItem value="">Standard (default)</MenuItem>
              {prof?.profiles.map((p) => (
                <MenuItem key={p.id} value={p.id}>{p.title || p.id}</MenuItem>
              ))}
            </TextField>
            <Button variant="contained" sx={{ mt: 0.5 }} disabled={!host || runMut.isPending} onClick={() => runMut.mutate()}>
              {runMut.isPending ? "Starting…" : "Run scan"}
            </Button>
          </Stack>

          <FormControlLabel
            control={<Checkbox size="small" checked={skipExpensive} onChange={(e) => setSkipExpensive(e.target.checked)} />}
            label="Skip slow filesystem rules (home-dir / world-writable / SUID audits)"
          />
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1, ml: 4, mt: -0.5 }}>
            Much faster on hosts with many files; those rules are excluded from this scan and its score.
          </Typography>
          <TextField
            size="small" fullWidth label="Also skip these rule IDs (optional, comma/space separated)"
            value={skipRulesText} onChange={(e) => setSkipRulesText(e.target.value)} sx={{ mb: 1 }}
            placeholder="xccdf_org.ssgproject.content_rule_…"
          />

          {/* The picker needs the scanner installed AND content matching the host OS. */}
          {prof && (!prof.installed || !prof.exact) && (
            prof.installing || prepareMut.isPending ? (
              <Alert severity="info" icon={<CircularProgress size={18} />} sx={{ mb: 2 }}>
                {prof.installed
                  ? "Provisioning SCAP content matching this host's OS… the profile list updates when it's ready."
                  : "Installing OpenSCAP on the host… the profile list populates when it's ready (first install can take a few minutes)."}
                {" "}You can also run the default profile now.
              </Alert>
            ) : (
              <Alert severity="info" sx={{ mb: 2 }} action={
                <Button color="inherit" size="small" onClick={() => prepareMut.mutate()}>
                  {prof.installed ? "Provision content" : "Install scanner"}
                </Button>
              }>
                {prof.installed
                  ? "This host's OS is newer than its installed SCAP content, so only older-version profiles are shown. Provision matching content to scan against the right benchmark."
                  : "OpenSCAP isn't installed on this host yet, so only the default profile is available. Install it to choose a specific profile, or just run the default."}
              </Alert>
            )
          )}
          {runMut.isError && <Alert severity="error" sx={{ mb: 2 }}>Could not start the scan.</Alert>}

          <Typography variant="overline" color="text.secondary">History</Typography>
          <Stack spacing={1} sx={{ mt: 0.5 }}>
            {scans.map((s) => (
              <ScanRow key={s.id} scan={s} token={token} onView={() => setReportId(s.id)}
                onRemediate={canRemediate ? () => setRemediateScan(s) : undefined} />
            ))}
            {scans.length === 0 && <Typography variant="body2" color="text.secondary">No scans yet.</Typography>}
          </Stack>
        </DialogContent>
        <DialogActions><Button onClick={onClose}>Close</Button></DialogActions>
      </Dialog>
      <ScanReportViewer scanId={reportId} token={token} onClose={() => setReportId(null)} />
      <RemediateDialog
        key={remediateScan?.id ?? "rem-none"} scan={remediateScan}
        onClose={() => setRemediateScan(null)}
        onApplied={() => void qc.invalidateQueries({ queryKey: ["host-scans", hostId] })}
      />
    </>
  );
}

function ScanRow({ scan, token, onView, onRemediate }: {
  scan: HostScan; token: string; onView: () => void; onRemediate?: () => void;
}) {
  const active = scan.status === "pending" || scan.status === "running";
  return (
    <Paper variant="outlined" sx={{ p: 1.5 }}>
      <Stack direction="row" alignItems="center" spacing={1.5}>
        <Chip size="small" label={scan.status} color={scanColor(scan.status)} />
        <Box sx={{ flexGrow: 1, minWidth: 0 }}>
          <Typography variant="body2" noWrap>{scan.profileTitle || scan.profile || "Standard profile"}</Typography>
          <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>
            {fmtDate(scan.createdAt)}{scan.scheduled ? " · scheduled" : scan.requester ? ` · ${scan.requester}` : ""}
            {scan.benchmark ? ` · ${scan.benchmark.split("/").pop()}` : ""}
            {scan.skipRules && scan.skipRules.length > 0 ? ` · ${scan.skipRules.length} rules skipped` : ""}
          </Typography>
        </Box>
        {active && <CircularProgress size={18} />}
        {scan.status === "failed" && (
          <Tooltip title={scan.error || "failed"}>
            <Typography variant="caption" color="error" sx={{ maxWidth: 200 }} noWrap>{scan.error || "failed"}</Typography>
          </Tooltip>
        )}
        {scan.status === "completed" && (
          <Stack direction="row" spacing={1.5} alignItems="center">
            <Box sx={{ textAlign: "right" }}>
              <Typography variant="body2">{scan.score != null ? `${Math.round(scan.score)}%` : "—"}</Typography>
              <Typography variant="caption" color="text.secondary">
                <span style={{ color: "#2e7d32" }}>{scan.passCount} pass</span>
                {" · "}
                <span style={{ color: "#c62828" }}>{scan.failCount} fail</span>
              </Typography>
            </Box>
            <Button size="small" onClick={onView}>View</Button>
            <Button size="small" component="a" href={scanReportUrl(scan.id, token, true)}>Download</Button>
            {onRemediate && scan.failCount > 0 && (
              <Button size="small" color="warning" onClick={onRemediate}>Remediate</Button>
            )}
          </Stack>
        )}
      </Stack>
    </Paper>
  );
}

// RemediateDialog lists a scan's failed rules, lets an admin select which to fix,
// preview the exact bash, and apply (with an extra confirm for rules that could
// cut off Fleet's own access). It then polls the run and shows the re-scan score.
function RemediateDialog({ scan, onClose, onApplied }: {
  scan: HostScan | null; onClose: () => void; onApplied: () => void;
}) {
  const scanId = scan?.id ?? "";
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [confirm, setConfirm] = useState(false);
  const [confirmCP, setConfirmCP] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [run, setRun] = useState<{ status: string; exitCode?: number; output?: string; rescanId?: string; error?: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["scan-findings", scanId],
    queryFn: () => listFindings(scanId),
    enabled: Boolean(scan),
    retry: false,
  });
  const findings = data?.findings ?? [];
  const controlPlane = Boolean(data?.controlPlane);

  const selectedIds = [...selected];
  const anyImpacting = findings.some((f) => selected.has(f.ruleId) && f.accessImpacting);
  const toggle = (id: string) => setSelected((s) => {
    const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n;
  });

  async function doPreview() {
    setError(null); setPreview(null); setBusy(true);
    try { setPreview(await previewRemediation(scanId, selectedIds)); }
    catch { setError("Could not generate the preview."); }
    finally { setBusy(false); }
  }

  async function apply() {
    setError(null); setBusy(true); setRun({ status: "running" });
    try {
      const rec = await remediate(scanId, selectedIds, confirm, confirmCP);
      for (let i = 0; i < 200; i++) {
        await new Promise((r) => setTimeout(r, 2000));
        const st = await remediationStatus(rec.id);
        if (st.status !== "pending" && st.status !== "running") { setRun(st); onApplied(); break; }
      }
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg || "Remediation failed to start.");
      setRun(null);
    } finally { setBusy(false); }
  }

  return (
    <Dialog open={Boolean(scan)} onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>Remediate failures · {scan?.profileTitle || scan?.profile}</DialogTitle>
      <DialogContent dividers>
        <Alert severity="warning" sx={{ mb: 2 }}>
          Remediation <b>changes this host's configuration</b>. Rules marked <b>⚠ access-impacting</b>
          (SSH, firewall, account lockout) can cut off Fleet's own access — review the preview and
          apply with care.
        </Alert>
        {controlPlane && (
          <Alert severity="error" sx={{ mb: 2 }}>
            This is a <b>Fleet control-plane host</b>. Hardening it can lock Fleet out of the entire
            fleet — for example, an <code>ip_forward</code> or <code>rp_filter</code> sysctl can break
            the container/WireGuard networking that serves this UI. Only proceed if you have out-of-band
            (console) access to recover.
          </Alert>
        )}
        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
        {isLoading && <Box sx={{ p: 2, textAlign: "center" }}><CircularProgress /></Box>}

        {!run && findings.length > 0 && (
          <Stack spacing={0.5} sx={{ mb: 2 }}>
            {findings.map((f) => (
              <FindingRow key={f.ruleId} f={f} checked={selected.has(f.ruleId)} onToggle={() => toggle(f.ruleId)} />
            ))}
          </Stack>
        )}
        {!run && !isLoading && findings.length === 0 && (
          <Typography variant="body2" color="text.secondary">No failed rules to remediate.</Typography>
        )}

        {anyImpacting && !run && (
          <FormControlLabel
            control={<Checkbox checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />}
            label="I understand the selected access-impacting rules may cut off Fleet's access to this host."
          />
        )}
        {controlPlane && !run && (
          <FormControlLabel
            control={<Checkbox checked={confirmCP} onChange={(e) => setConfirmCP(e.target.checked)} />}
            label="I understand this is a Fleet control-plane host and remediating it may lock Fleet out of the fleet."
          />
        )}

        {preview != null && (
          <Box sx={{ mt: 1 }}>
            <Typography variant="overline" color="text.secondary">Remediation script (preview)</Typography>
            <Box component="pre" sx={{ m: 0, p: 1.5, bgcolor: "action.hover", borderRadius: 1, fontSize: 12, overflow: "auto", maxHeight: 280 }}>
              {preview || "(oscap produced no fix for the selected rules)"}
            </Box>
          </Box>
        )}

        {run && (
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 1 }}>
              Remediation {run.status}{run.exitCode != null ? ` (exit ${run.exitCode})` : ""}
              {run.status === "running" && <CircularProgress size={14} sx={{ ml: 1 }} />}
            </Typography>
            {run.error && <Alert severity="error" sx={{ mb: 1 }}>{run.error}</Alert>}
            {run.output && (
              <Box component="pre" sx={{ m: 0, p: 1.5, bgcolor: "action.hover", borderRadius: 1, fontSize: 12, overflow: "auto", maxHeight: 280 }}>
                {run.output}
              </Box>
            )}
            {run.status === "completed" && (
              <Typography variant="body2" sx={{ mt: 1 }} color="text.secondary">
                A verification re-scan was run — see the latest scan in the history for the new score.
              </Typography>
            )}
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
        {!run && (
          <>
            <Button disabled={selectedIds.length === 0 || busy} onClick={doPreview}>Preview</Button>
            <Button
              variant="contained" color="warning"
              disabled={selectedIds.length === 0 || busy || (anyImpacting && !confirm) || (controlPlane && !confirmCP)}
              onClick={apply}
            >
              Apply {selectedIds.length > 0 ? `(${selectedIds.length})` : ""}
            </Button>
          </>
        )}
      </DialogActions>
    </Dialog>
  );
}

function FindingRow({ f, checked, onToggle }: { f: ScanFinding; checked: boolean; onToggle: () => void }) {
  const sevColor = f.severity === "high" ? "error" : f.severity === "medium" ? "warning" : "default";
  return (
    <Stack direction="row" alignItems="center" spacing={1}>
      <Checkbox size="small" checked={checked} onChange={onToggle} sx={{ p: 0.5 }} />
      {f.severity && <Chip size="small" label={f.severity} color={sevColor as "error" | "warning" | "default"} variant="outlined" />}
      {f.accessImpacting && <Tooltip title="May cut off Fleet's access (SSH/firewall/lockout)"><Chip size="small" color="warning" label="⚠ access" /></Tooltip>}
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="body2" noWrap>{f.title}</Typography>
        <Typography variant="caption" color="text.secondary" noWrap sx={{ display: "block" }}>{f.ruleId}</Typography>
      </Box>
    </Stack>
  );
}

function ScanReportViewer({ scanId, token, onClose }: { scanId: string | null; token: string; onClose: () => void }) {
  // Fetch the HTML and render via srcdoc (sandboxed) rather than framing the URL,
  // so a reverse proxy's X-Frame-Options can't block the embed.
  const { data: html, isLoading, isError } = useQuery({
    queryKey: ["scan-report", scanId],
    queryFn: () => fetchScanReport(scanId as string, token),
    enabled: Boolean(scanId),
  });
  return (
    <Dialog open={Boolean(scanId)} onClose={onClose} fullWidth maxWidth="lg" PaperProps={{ sx: { height: "90vh" } }}>
      <DialogTitle sx={{ display: "flex", alignItems: "center", gap: 1 }}>
        <span style={{ flexGrow: 1 }}>Scan report</span>
        {scanId && <Button size="small" component="a" href={scanReportUrl(scanId, token, true)}>Download</Button>}
        <Button size="small" onClick={onClose}>Close</Button>
      </DialogTitle>
      <DialogContent sx={{ p: 0 }}>
        {isLoading && <Box sx={{ p: 4, textAlign: "center" }}><CircularProgress /></Box>}
        {isError && <Alert severity="error" sx={{ m: 2 }}>Could not load the report.</Alert>}
        {html && (
          <iframe
            title="OpenSCAP report"
            srcDoc={html}
            sandbox="allow-scripts"
            style={{ width: "100%", height: "100%", border: "none" }}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

// HostDetailsDialog shows collected facts about a host (distro, kernel, CPU,
// memory) plus live status. It fetches the single host on demand — so the list
// payload stays light at scale — and seeds from the row for an instant render,
// then refreshes to the latest monitor-collected values.
function HostDetailsDialog({ host, onClose }: { host: Host | null; onClose: () => void }) {
  const { data } = useQuery({
    queryKey: ["host", host?.id],
    queryFn: () => getHost(host!.id),
    enabled: Boolean(host),
    initialData: host ?? undefined,
  });
  const h = data ?? host;
  const inv = h?.inventory;
  const st = h?.status;
  const met = h?.metrics;
  // RDP (Windows) hosts have no SSH/kernel/apt-updates and aren't on the WireGuard
  // overlay; their facts come from WinRM. Hide the fields that don't apply.
  const isRDP = h?.protocol === "rdp";
  const { data: software = [] } = useQuery({
    queryKey: ["host-software", host?.id],
    queryFn: () => listHostSoftware(host!.id),
    enabled: Boolean(host) && isRDP,
  });
  const refresh = useMutation({ mutationFn: () => refreshHostFacts(host!.id) });
  const qc = useQueryClient();
  const [maintAnchor, setMaintAnchor] = useState<null | HTMLElement>(null);
  const setMaint = useMutation({
    mutationFn: (minutes: number) => setHostMaintenance(host!.id, minutes),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["host", host?.id] }); qc.invalidateQueries({ queryKey: ["hosts"] }); },
  });
  const clearMaint = useMutation({
    mutationFn: () => clearHostMaintenance(host!.id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["host", host?.id] }); qc.invalidateQueries({ queryKey: ["hosts"] }); },
  });
  const inMaint = h ? maintenanceActive(h) : false;
  return (
    <Dialog open={Boolean(host)} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>
        {h?.hostname ?? "Host"} · details
        {inMaint && (
          <Tooltip title={`Alerts silenced until ${fmtDate(h!.maintenanceUntil!)}`}>
            <Chip size="small" color="warning" label="In maintenance" sx={{ ml: 1 }} />
          </Tooltip>
        )}
      </DialogTitle>
      <DialogContent dividers>
        <Typography variant="overline" color="text.secondary">System</Typography>
        <DetailRows rows={[
          ["Operating system", inv?.osName],
          ["OS version", inv?.osVersion],
          ...(isRDP ? [] : [["Kernel", inv?.kernelVersion] as [string, string | undefined]]),
          ["Architecture", inv?.architecture],
          ["CPUs", inv?.cpuCount ? String(inv.cpuCount) : ""],
          ["Memory", fmtMem(inv?.memoryMb)],
          ...(isRDP ? [] : [
            ["SSH", inv?.sshVersion] as [string, string | undefined],
            ["Updates available", inv?.updatesAvailable != null
              ? `${inv.updatesAvailable}${inv.securityUpdates ? ` (${inv.securityUpdates} security)` : ""}`
              : ""] as [string, string | undefined],
          ]),
          ["Facts collected", inv?.collectedAt ? fmtDate(inv.collectedAt) : ""],
        ]} />
        <Typography variant="overline" color="text.secondary" sx={{ display: "block", mt: 2 }}>Status</Typography>
        <DetailRows rows={[
          ["State", st?.status],
          ["Uptime", fmtUptime(st?.uptimeSeconds)],
          ["Latency", st?.latencyMs != null ? `${st.latencyMs} ms` : ""],
          ...(isRDP ? [] : [["WireGuard", st ? (st.wgOk ? "healthy" : "—") : ""] as [string, string | undefined]]),
          ["Last checked", st?.checkedAt ? fmtDate(st.checkedAt) : ""],
        ]} />
        {met && (
          <>
            <Typography variant="overline" color="text.secondary" sx={{ display: "block", mt: 2 }}>Resources</Typography>
            <DetailRows rows={[
              ["Memory", met.memTotalMb ? `${met.memUsedPct != null ? Math.round(met.memUsedPct) + "% used · " : ""}${fmtMem(met.memTotalMb)} total` : ""],
              ["Load 1/5/15m", met.load1 != null ? `${met.load1} / ${met.load5 ?? "—"} / ${met.load15 ?? "—"}${met.loadPerCore != null ? `  (${met.loadPerCore.toFixed(2)}/core)` : ""}` : ""],
              ["Primary IP", met.primaryIp],
              ["Gateway", met.network?.defaultGateway],
            ]} />
            {met.disk && met.disk.length > 0 && (
              <Stack spacing={0.5} sx={{ mt: 0.5 }}>
                {met.disk.map((d) => (
                  <Stack key={d.mount} direction="row" spacing={2}>
                    <Typography variant="body2" color="text.secondary" sx={{ width: 150, flexShrink: 0 }}>{d.mount}</Typography>
                    <Typography variant="body2" sx={{ fontFamily: "monospace" }}>
                      {fmtBytes(d.usedBytes)} / {fmtBytes(d.sizeBytes)} ({Math.round(d.usePct)}% used)
                    </Typography>
                  </Stack>
                ))}
              </Stack>
            )}
          </>
        )}
        {isRDP && software.length > 0 && (
          <>
            <Typography variant="overline" color="text.secondary" sx={{ display: "block", mt: 2 }}>
              Installed software ({software.length})
            </Typography>
            <Box sx={{ maxHeight: 220, overflow: "auto", mt: 0.5 }}>
              {software.map((s, i) => (
                <Stack key={`${s.name}-${s.version}-${i}`} direction="row" spacing={2} sx={{ py: 0.25 }}>
                  <Typography variant="body2" sx={{ flexGrow: 1 }} noWrap title={s.name}>{s.name}</Typography>
                  <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "monospace", flexShrink: 0 }}>
                    {s.version || "—"}
                  </Typography>
                </Stack>
              ))}
            </Box>
          </>
        )}
        {!inv && (
          <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
            No facts collected yet — they're gathered at enrollment and refreshed periodically by the monitor.
          </Typography>
        )}
      </DialogContent>
      <DialogActions>
        <Tooltip title="Re-collect pending updates and inventory on the next monitor check (instead of waiting for the hourly refresh)">
          <Button
            onClick={() => refresh.mutate()}
            disabled={refresh.isPending || refresh.isSuccess}
          >
            {refresh.isSuccess ? "Refresh queued" : refresh.isPending ? "Queuing…" : "Refresh facts"}
          </Button>
        </Tooltip>
        {inMaint ? (
          <Button color="warning" onClick={() => clearMaint.mutate()} disabled={clearMaint.isPending}>
            End maintenance
          </Button>
        ) : (
          <Tooltip title="Silence offline / updates-pending / scan-failure alerts for this host while you patch or reboot it">
            <Button onClick={(e) => setMaintAnchor(e.currentTarget)} disabled={setMaint.isPending}>
              Silence alerts
            </Button>
          </Tooltip>
        )}
        <Menu anchorEl={maintAnchor} open={Boolean(maintAnchor)} onClose={() => setMaintAnchor(null)}>
          {[["1 hour", 60], ["4 hours", 240], ["8 hours", 480], ["24 hours", 1440]].map(([label, mins]) => (
            <MenuItem
              key={label as string}
              onClick={() => { setMaint.mutate(mins as number); setMaintAnchor(null); }}
            >
              {label}
            </MenuItem>
          ))}
        </Menu>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

function DetailRows({ rows }: { rows: [string, string | undefined][] }) {
  return (
    <Stack spacing={0.5} sx={{ mt: 0.5 }}>
      {rows.map(([label, value]) => (
        <Stack key={label} direction="row" spacing={2}>
          <Typography variant="body2" color="text.secondary" sx={{ width: 150, flexShrink: 0 }}>{label}</Typography>
          <Typography variant="body2" sx={{ fontFamily: "monospace", wordBreak: "break-word" }}>{value || "—"}</Typography>
        </Stack>
      ))}
    </Stack>
  );
}

function fmtBytes(b: number): string {
  if (!b) return "0";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let v = b, i = 0;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${u[i]}`;
}

function fmtMem(mb?: number): string {
  if (!mb) return "";
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`;
}

function fmtUptime(secs?: number): string {
  if (!secs || secs <= 0) return "";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// HostAccessDialog manages who can reach a host: the groups it belongs to and
// individual users granted direct access. Access to a host is the union of
// these (plus any active just-in-time grants).
function HostAccessDialog({ host, onClose }: { host: Host | null; onClose: () => void }) {
  const qc = useQueryClient();
  const hostId = host?.id ?? "";
  const [userToAdd, setUserToAdd] = useState("");
  const [groupToAdd, setGroupToAdd] = useState("");

  const { data: access } = useQuery({
    queryKey: ["host-access", hostId],
    queryFn: () => getHostAccess(hostId),
    enabled: Boolean(host),
  });
  const { data: allGroups } = useQuery({ queryKey: ["groups"], queryFn: listGroups, enabled: Boolean(host) });
  const { data: allUsers } = useQuery({ queryKey: ["users"], queryFn: listUsers, enabled: Boolean(host) });

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ["host-access", hostId] });
    void qc.invalidateQueries({ queryKey: ["hosts"] });
  };
  const mut = (fn: () => Promise<void>) => async () => { await fn(); refresh(); };

  const addUserMut = useMutation({ mutationFn: (uid: string) => addHostUser(hostId, uid), onSuccess: () => { setUserToAdd(""); refresh(); } });
  const rmUserMut = useMutation({ mutationFn: (uid: string) => removeHostUser(hostId, uid), onSuccess: refresh });
  const addGroupMut = useMutation({ mutationFn: (gid: string) => addHostGroup(hostId, gid), onSuccess: () => { setGroupToAdd(""); refresh(); } });
  const rmGroupMut = useMutation({ mutationFn: (gname: string) => {
    const g = (allGroups ?? []).find((x) => x.name === gname);
    return g ? removeHostGroup(hostId, g.id) : Promise.resolve();
  }, onSuccess: refresh });

  const grantedGroupNames = new Set(access?.groups ?? []);
  const grantedUserIds = new Set((access?.users ?? []).map((u) => u.id));
  const availableGroups = (allGroups ?? []).filter((g) => !grantedGroupNames.has(g.name));
  const availableUsers = (allUsers ?? []).filter((u) => !grantedUserIds.has(u.id));

  return (
    <Dialog open={Boolean(host)} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Access — {host?.hostname}</DialogTitle>
      <DialogContent dividers>
        <Typography variant="subtitle2" gutterBottom>Groups</Typography>
        <Stack direction="row" spacing={1} sx={{ flexWrap: "wrap", mb: 1 }}>
          {(access?.groups ?? []).length === 0 && (
            <Typography variant="body2" color="text.secondary">No groups assigned.</Typography>
          )}
          {(access?.groups ?? []).map((g) => (
            <Chip key={g} label={g} onDelete={mut(() => rmGroupMut.mutateAsync(g))} />
          ))}
        </Stack>
        <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
          <TextField
            select size="small" label="Add group" value={groupToAdd}
            onChange={(e) => setGroupToAdd(e.target.value)} sx={{ minWidth: 220 }}
          >
            {availableGroups.length === 0 && <MenuItem value="" disabled>No more groups</MenuItem>}
            {availableGroups.map((g) => <MenuItem key={g.id} value={g.id}>{g.name}</MenuItem>)}
          </TextField>
          <Button variant="outlined" disabled={!groupToAdd || addGroupMut.isPending} onClick={() => addGroupMut.mutate(groupToAdd)}>Add</Button>
        </Stack>

        <Divider sx={{ my: 1 }} />

        <Typography variant="subtitle2" gutterBottom>Individual users (direct access)</Typography>
        <List dense>
          {(access?.users ?? []).length === 0 && (
            <Typography variant="body2" color="text.secondary">No users granted direct access.</Typography>
          )}
          {(access?.users ?? []).map((u) => (
            <ListItem key={u.id} disableGutters>
              <ListItemText primary={u.username} secondary={u.displayName || u.email} />
              <ListItemSecondaryAction>
                <IconButton edge="end" size="small" color="error" disabled={rmUserMut.isPending} onClick={() => rmUserMut.mutate(u.id)}>
                  <DeleteIcon fontSize="small" />
                </IconButton>
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
        <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
          <TextField
            select size="small" label="Add user" value={userToAdd}
            onChange={(e) => setUserToAdd(e.target.value)} sx={{ minWidth: 220 }}
          >
            {availableUsers.length === 0 && <MenuItem value="" disabled>No more users</MenuItem>}
            {availableUsers.map((u) => <MenuItem key={u.id} value={u.id}>{u.username}</MenuItem>)}
          </TextField>
          <Button variant="outlined" disabled={!userToAdd || addUserMut.isPending} onClick={() => addUserMut.mutate(userToAdd)}>Add</Button>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}

// EnrollCredsDialog collects how to reach the host for the initial bootstrap:
// an SSH password (installs CA trust + WireGuard on a brand-new host), or the
// session certificate when the host already trusts the Fleet CA.
function EnrollCredsDialog({
  host, onClose, onSubmit, onPipeFinish,
}: {
  host: Host | null;
  onClose: () => void;
  onSubmit: (params: EnrollParams) => void;
  onPipeFinish: (hostPublicKey: string) => void;
}) {
  const [method, setMethod] = useState<"password" | "key" | "agent" | "pipe" | "trusted">("password");
  const [bootstrapUser, setBootstrapUser] = useState("root");
  const [password, setPassword] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [keyPassphrase, setKeyPassphrase] = useState("");
  const [sudoPassword, setSudoPassword] = useState("");
  const [wgEndpoint, setWgEndpoint] = useState("");
  const [viaJump, setViaJump] = useState(false);
  const [skipWireGuard, setSkipWireGuard] = useState(false);
  // No-install (ssh-pipe) flow state.
  const [sshTarget, setSshTarget] = useState("");
  const [hostPubKey, setHostPubKey] = useState("");
  const token = useAuthStore((s) => s.accessToken);
  const scriptUrl =
    `${window.location.origin}/api/v1/hosts/${host?.id ?? "<host-id>"}/enroll/script` +
    (wgEndpoint ? `?wgEndpoint=${encodeURIComponent(wgEndpoint)}` : "");
  const pipeCommand =
    `curl -fsSL -H "Authorization: Bearer ${token ?? "<YOUR_TOKEN>"}" \\\n` +
    `  "${scriptUrl}" \\\n` +
    `  | ssh ${sshTarget || "<user@host>"} sudo bash`;

  // Pre-fill the jump host's WireGuard endpoint with the configured default.
  const { data: nextWG } = useQuery({ queryKey: ["next-wg"], queryFn: nextWGAddress, enabled: Boolean(host) });
  useEffect(() => {
    if (nextWG?.jumpEndpoint && wgEndpoint === "") setWgEndpoint(nextWG.jumpEndpoint);
  }, [nextWG?.jumpEndpoint, wgEndpoint]);

  // Download the enrollment script (bash for SSH hosts, PowerShell for Windows).
  const downloadScript = async (ext: string) => {
    const res = await fetch(scriptUrl, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
    const text = await res.text();
    const url = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `fleet-enroll-${host?.hostname ?? "host"}.${ext}`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  // Windows/RDP hosts join the overlay via a PowerShell WireGuard script (dial-out),
  // then the operator pastes the reported public key back — no SSH/CA trust.
  if (host?.protocol === "rdp") {
    return (
      <Dialog open={Boolean(host)} onClose={onClose} fullWidth maxWidth="sm">
        <DialogTitle>Enroll {host.hostname} (Windows / WireGuard)</DialogTitle>
        <DialogContent>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1, mb: 2 }}>
            Joins this Windows host to the WireGuard overlay by dialing out to the jump host,
            so its RDP session and fact collection are reachable from anywhere — no inbound
            firewall rules. Run the script once, elevated, on the host.
          </Typography>
          <Stack spacing={2}>
            <TextField
              label="Jump host WireGuard endpoint" value={wgEndpoint}
              onChange={(e) => setWgEndpoint(e.target.value)}
              helperText="host:port the Windows client dials (publicly reachable)"
            />
            <Box>
              <Button variant="outlined" onClick={() => void downloadScript("ps1")}>
                Download PowerShell script (.ps1)
              </Button>
              <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
                On {host.hostname}: open an <b>elevated PowerShell</b> and run the downloaded
                <code> fleet-enroll-{host.hostname}.ps1</code> (you may need
                <code> Set-ExecutionPolicy -Scope Process Bypass</code> first). It installs
                WireGuard, brings up the tunnel, and prints a public key.
              </Typography>
            </Box>
            <TextField
              label="WireGuard public key (from the script output)" value={hostPubKey}
              onChange={(e) => setHostPubKey(e.target.value)} fullWidth
              helperText="Paste the key the script printed, then finish."
            />
          </Stack>
        </DialogContent>
        <DialogActions>
          <Button onClick={onClose}>Close</Button>
          <Button variant="contained" disabled={hostPubKey.trim() === ""}
            onClick={() => onPipeFinish(hostPubKey.trim())}>
            Finish enrollment
          </Button>
        </DialogActions>
      </Dialog>
    );
  }

  return (
    <Dialog open={Boolean(host)} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Enroll {host?.hostname}</DialogTitle>
      <DialogContent>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 1, mb: 2 }}>
          Enrollment installs the SSH CA trust and WireGuard on the host, joins it to the
          VPN overlay, and verifies per-user certificate login through the jump host.
        </Typography>
        <FormControl sx={{ mb: 2 }}>
          <FormLabel>How should we reach this host first?</FormLabel>
          <RadioGroup value={method} onChange={(e) => setMethod(e.target.value as "password" | "key" | "agent" | "trusted")}>
            <FormControlLabel
              value="password" control={<Radio />}
              label="SSH password — install everything (new/existing host with no setup)"
            />
            <FormControlLabel
              value="key" control={<Radio />}
              label="SSH private key — for hosts with password auth disabled (uses a key already in authorized_keys)"
            />
            <FormControlLabel
              value="agent" control={<Radio />}
              label="SSH agent — run a small bridge from your laptop; the key never leaves your machine"
            />
            <FormControlLabel
              value="pipe" control={<Radio />}
              label="No install — pipe a script through your own ssh (nothing to install, key stays local)"
            />
            <FormControlLabel
              value="trusted" control={<Radio />}
              label="Host already trusts the Fleet CA (re-provision only)"
            />
          </RadioGroup>
        </FormControl>
        {method === "password" && (
          <Stack spacing={2}>
            <TextField
              label="SSH user" value={bootstrapUser}
              onChange={(e) => setBootstrapUser(e.target.value)}
              helperText="A user with sudo, or root"
            />
            <TextField
              label="SSH password" type="password" value={password}
              onChange={(e) => setPassword(e.target.value)} autoFocus
              helperText="Used once to bootstrap trust; never stored"
            />
            <TextField
              label="Sudo password (optional)" type="password" value={sudoPassword}
              onChange={(e) => setSudoPassword(e.target.value)}
              helperText="Only if this user's sudo requires a password different from the SSH password"
            />
          </Stack>
        )}
        {method === "agent" && (
          <Alert severity="info" sx={{ mt: 1 }}>
            The browser can't reach your SSH agent, so run the bridge from your
            laptop — your key never leaves your machine (only signatures are
            forwarded). With your key loaded (<code>ssh-add</code>), run:
            <Box
              component="pre"
              sx={{ mt: 1, p: 1, bgcolor: "action.hover", borderRadius: 1, fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all" }}
            >
{`fleet-enroll-agent \\
  -url ${window.location.origin} \\
  -host ${host?.id ?? "<host-id>"} \\
  -token <YOUR_TOKEN> \\
  -bootstrap-user <ssh-user>`}
            </Box>
            Pass <code>-via-jump</code> if the backend can't reach the host
            directly. Build the bridge with <code>make enroll-agent</code>.
          </Alert>
        )}
        {method === "pipe" && (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Nothing to install. <b>Step 1:</b> run this in your terminal — it
              fetches a bootstrap script and pipes it through <i>your own</i> ssh.
              Your key never leaves your machine.
            </Typography>
            <TextField
              label="Your SSH target (user@host)" value={sshTarget}
              onChange={(e) => setSshTarget(e.target.value)}
              placeholder="opsadmin@web-01" size="small"
              helperText="The host login you already use; needs sudo on the host"
            />
            <Box sx={{ position: "relative" }}>
              <Box
                component="pre"
                sx={{ p: 1.5, pr: 5, bgcolor: "action.hover", borderRadius: 1, fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all", m: 0 }}
              >
                {pipeCommand}
              </Box>
              <Tooltip title="Copy command">
                <IconButton
                  size="small" sx={{ position: "absolute", top: 4, right: 4 }}
                  onClick={() => navigator.clipboard?.writeText(pipeCommand)}
                >
                  <ContentCopyIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
            <Typography variant="body2" color="text.secondary">
              <b>Step 2:</b> the script prints a <b>host public key</b> at the end.
              Paste it here and finish — Fleet adds the jump-host peer and verifies
              certificate login.
            </Typography>
            <TextField
              label="Host public key" value={hostPubKey}
              onChange={(e) => setHostPubKey(e.target.value)}
              fullWidth size="small"
              placeholder="base64 key printed by the script"
              inputProps={{ style: { fontFamily: "monospace", fontSize: 12 } }}
            />
          </Stack>
        )}
        {method === "key" && (
          <Stack spacing={2}>
            <TextField
              label="SSH user" value={bootstrapUser}
              onChange={(e) => setBootstrapUser(e.target.value)}
              helperText="The user whose key is in the host's authorized_keys (e.g. root or a sudo user)"
            />
            <TextField
              label="Private key (PEM)" value={privateKey}
              onChange={(e) => setPrivateKey(e.target.value)} autoFocus
              multiline minRows={4} fullWidth
              placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----"}
              helperText="An existing key already trusted on the host. Used once over HTTPS for bootstrap; never stored."
              inputProps={{ style: { fontFamily: "monospace", fontSize: 12 } }}
            />
            <TextField
              label="Key passphrase (optional)" type="password" value={keyPassphrase}
              onChange={(e) => setKeyPassphrase(e.target.value)}
              helperText="Only if the private key is encrypted"
            />
            <TextField
              label="Sudo password (optional)" type="password" value={sudoPassword}
              onChange={(e) => setSudoPassword(e.target.value)}
              helperText="Only if this user's sudo requires a password (leave blank for root or passwordless sudo)"
            />
          </Stack>
        )}
        <FormControlLabel
          sx={{ mt: 2, display: "block" }}
          control={<Checkbox checked={skipWireGuard} onChange={(e) => setSkipWireGuard(e.target.checked)} />}
          label="Directly reachable from the jump host — skip WireGuard"
        />
        {skipWireGuard && (
          <Typography variant="caption" color="text.secondary" sx={{ display: "block", ml: 4, mb: 1 }}>
            For hosts on the jump host's LAN (or the host running Fleet itself). No overlay is set up;
            the host is reached at its management address through the jump host.
          </Typography>
        )}
        <TextField
          fullWidth sx={{ mt: 2 }}
          label="Jump host WireGuard endpoint" value={wgEndpoint}
          onChange={(e) => setWgEndpoint(e.target.value)}
          disabled={skipWireGuard}
          helperText="Public address:port the HOST uses to reach the VPN server (e.g. vpn.example.com:51820). Must be resolvable from the host — not an internal Docker name."
        />
        <FormControlLabel
          sx={{ mt: 1 }}
          control={<Checkbox checked={viaJump} onChange={(e) => setViaJump(e.target.checked)} />}
          label="Reach this host through the jump host (backend can't reach it directly)"
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        {method === "pipe" ? (
          <Button
            variant="contained"
            disabled={hostPubKey.trim() === ""}
            onClick={() => onPipeFinish(hostPubKey.trim())}
          >
            Finish enrollment
          </Button>
        ) : (
          <Button
            variant="contained"
            disabled={method === "agent" || (method === "password" && password === "") || (method === "key" && privateKey.trim() === "")}
            onClick={() => onSubmit({ method, bootstrapUser, password, privateKey, keyPassphrase, sudoPassword, wgEndpoint, viaJump, skipWireGuard })}
          >
            Enroll
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}

// EnrollDialog streams the enrollment job's step results (provisioning the
// WireGuard peer on the jump host, the interface on the host, and verification).
interface EnrollDialogProps {
  open: boolean;
  pending: boolean;
  result: EnrollmentResult | null;
  error: string | null;
  onClose: () => void;
}

function EnrollDialog({ open, pending, result, error, onClose }: EnrollDialogProps) {
  const stepColor = (s: string) =>
    s === "ok" ? "success.main" : s === "failed" ? "error.main" : s === "warning" ? "warning.main" : "text.secondary";
  const stepIcon = (s: string) =>
    s === "ok" ? "✓" : s === "failed" ? "✗" : s === "warning" ? "⚠" : "•";
  const steps = result?.job?.steps ?? [];
  const hasWarning = steps.some((s) => s.status === "warning");
  return (
    <Dialog open={open} onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>Host enrollment</DialogTitle>
      <DialogContent dividers>
        {pending && (
          <Stack direction="row" spacing={2} alignItems="center" sx={{ py: 2 }}>
            <CircularProgress size={22} />
            <Typography>Provisioning WireGuard and trust over SSH…</Typography>
          </Stack>
        )}
        {error && <Alert severity="error">{error}</Alert>}
        {result && (
          <>
            <Alert severity={hasWarning ? "warning" : "success"} sx={{ mb: 2 }}>
              Enrolled. Overlay address <b>{result.wgAddress}</b>; interface up on the host.
              {hasWarning && " Connectivity warning — see steps below."}
            </Alert>
            <List dense>
              {steps.map((st, i) => (
                <ListItem key={i} disableGutters>
                  <ListItemText
                    primary={
                      <Typography sx={{ color: stepColor(st.status) }}>
                        {stepIcon(st.status)} {st.name}
                      </Typography>
                    }
                    secondary={st.detail}
                  />
                </ListItem>
              ))}
            </List>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={pending}>Close</Button>
      </DialogActions>
    </Dialog>
  );
}
