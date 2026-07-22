import { useState } from "react";
import {
  Alert, Box, Button, Checkbox, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControlLabel, IconButton, MenuItem, Paper, Stack, Table, TableBody, TableCell, TableHead,
  TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import ViewListIcon from "@mui/icons-material/ViewList";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "../store/auth";
import {
  listClusters, createCluster, updateCluster, deleteCluster, listResources,
  type K8sCluster, type K8sClusterInput,
} from "../api/kubernetes";
import { listVaultSecrets } from "../api/vault";

const KINDS = ["pods", "deployments", "services", "namespaces", "nodes"];

// KubernetesPage: register clusters and browse resources through Fleet, which injects a
// vaulted bearer token and audits every call. Advanced users point kubectl at the proxy.
export function KubernetesPage() {
  const qc = useQueryClient();
  const has = useAuthStore((s) => s.has);
  const canManage = has("Kubernetes.Manage");
  const { data: clusters = [], isLoading } = useQuery({ queryKey: ["k8s-clusters"], queryFn: listClusters });
  const [editing, setEditing] = useState<K8sCluster | null>(null);
  const [creating, setCreating] = useState(false);
  const [browsing, setBrowsing] = useState<K8sCluster | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["k8s-clusters"] });
  const del = useMutation({ mutationFn: (id: string) => deleteCluster(id), onSuccess: invalidate });

  return (
    <Box sx={{ maxWidth: 1150 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Box>
          <Typography variant="h5">Kubernetes</Typography>
          <Typography variant="body2" color="text.secondary">
            Reach registered clusters through Fleet with a vaulted credential injected — you never see
            the token, and every call is audited. Browse resources here, or point kubectl at the proxy.
          </Typography>
        </Box>
        {canManage && <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>Register cluster</Button>}
      </Stack>

      <Paper variant="outlined" sx={{ mb: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell><TableCell>API server</TableCell>
              <TableCell>Credential</TableCell><TableCell>Namespace</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {clusters.map((c) => (
              <TableRow key={c.id} hover>
                <TableCell>{c.name}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{c.apiServer}</TableCell>
                <TableCell>{c.credentialName || <Typography variant="caption" color="warning.main">none</Typography>}</TableCell>
                <TableCell>{c.namespace}</TableCell>
                <TableCell align="right">
                  <Tooltip title="Browse resources"><span><IconButton size="small" color="primary"
                    disabled={!c.credentialId} onClick={() => setBrowsing(c)}><ViewListIcon fontSize="small" /></IconButton></span></Tooltip>
                  {canManage && <>
                    <Tooltip title="Edit"><IconButton size="small" onClick={() => setEditing(c)}><EditIcon fontSize="small" /></IconButton></Tooltip>
                    <Tooltip title="Delete"><IconButton size="small" color="error"
                      onClick={() => { if (window.confirm(`Delete cluster "${c.name}"?`)) del.mutate(c.id); }}>
                      <DeleteIcon fontSize="small" /></IconButton></Tooltip>
                  </>}
                </TableCell>
              </TableRow>
            ))}
            {clusters.length === 0 && (
              <TableRow><TableCell colSpan={5}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                  {isLoading ? "Loading…" : "No clusters registered yet."}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {browsing && <ResourceBrowser cluster={browsing} onClose={() => setBrowsing(null)} />}
      {creating && <ClusterDialog onClose={() => setCreating(false)} onSaved={() => { setCreating(false); invalidate(); }} />}
      {editing && <ClusterDialog cluster={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); invalidate(); }} />}
    </Box>
  );
}

function ResourceBrowser({ cluster, onClose }: { cluster: K8sCluster; onClose: () => void }) {
  const [kind, setKind] = useState("pods");
  const [namespace, setNamespace] = useState(cluster.namespace);
  const q = useQuery({
    queryKey: ["k8s-res", cluster.id, kind, namespace],
    queryFn: () => listResources(cluster.id, kind, namespace),
    retry: false,
  });
  const clusterWide = kind === "namespaces" || kind === "nodes";
  const err = (q.error as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1.5 }}>
        <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Resources — {cluster.name}</Typography>
        <Button size="small" onClick={onClose}>Close</Button>
      </Stack>
      <Stack direction="row" spacing={2} sx={{ mb: 1.5 }}>
        <TextField select size="small" label="Kind" value={kind} onChange={(e) => setKind(e.target.value)} sx={{ minWidth: 150 }}>
          {KINDS.map((k) => <MenuItem key={k} value={k}>{k}</MenuItem>)}
        </TextField>
        <TextField size="small" label="Namespace" value={namespace} disabled={clusterWide}
          onChange={(e) => setNamespace(e.target.value)} sx={{ width: 200 }} />
      </Stack>
      {q.isError && <Alert severity="error" sx={{ mb: 1 }}>{err || "Could not list resources."}</Alert>}
      <Table size="small">
        <TableHead>
          <TableRow><TableCell>Name</TableCell>{!clusterWide && <TableCell>Namespace</TableCell>}<TableCell>Status</TableCell><TableCell>Created</TableCell></TableRow>
        </TableHead>
        <TableBody>
          {(q.data ?? []).map((row, i) => (
            <TableRow key={i} hover>
              <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{row.name}</TableCell>
              {!clusterWide && <TableCell>{row.namespace}</TableCell>}
              <TableCell>{row.status ? <Chip size="small" variant="outlined" label={row.status} /> : "—"}</TableCell>
              <TableCell>{row.created}</TableCell>
            </TableRow>
          ))}
          {!q.isLoading && (q.data ?? []).length === 0 && !q.isError && (
            <TableRow><TableCell colSpan={4}><Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>No resources.</Typography></TableCell></TableRow>
          )}
        </TableBody>
      </Table>
    </Paper>
  );
}

function ClusterDialog({ cluster, onClose, onSaved }: { cluster?: K8sCluster; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<K8sClusterInput>({
    name: cluster?.name ?? "", apiServer: cluster?.apiServer ?? "https://", credentialId: cluster?.credentialId ?? null,
    caCert: "", insecureTls: cluster?.insecureTls ?? false, namespace: cluster?.namespace ?? "default",
    description: cluster?.description ?? "",
  });
  const { data: secrets = [] } = useQuery({ queryKey: ["vault-secrets"], queryFn: listVaultSecrets });
  const tokenSecrets = secrets.filter((s) => s.type === "api_key" || s.type === "password" || s.type === "generic");
  const save = useMutation({
    mutationFn: () => cluster ? updateCluster(cluster.id, form) : createCluster(form),
    onSuccess: onSaved,
  });
  const set = (k: keyof K8sClusterInput, v: string | boolean | null) => setForm((f) => ({ ...f, [k]: v }));
  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{cluster ? "Edit cluster" : "Register cluster"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <TextField label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} fullWidth autoFocus />
          <TextField label="API server (https://host:6443)" value={form.apiServer}
            onChange={(e) => set("apiServer", e.target.value)} fullWidth />
          <TextField select label="Credential (vault bearer token)" value={form.credentialId ?? ""}
            onChange={(e) => set("credentialId", e.target.value || null)} fullWidth
            helperText="A vault secret whose value is a Kubernetes bearer token (e.g. a ServiceAccount token).">
            <MenuItem value="">— none —</MenuItem>
            {tokenSecrets.map((s) => <MenuItem key={s.id} value={s.id}>{s.name}</MenuItem>)}
          </TextField>
          <TextField label="Default namespace" value={form.namespace} onChange={(e) => set("namespace", e.target.value)} fullWidth />
          <TextField label="API server CA certificate (PEM, optional)" value={form.caCert}
            onChange={(e) => set("caCert", e.target.value)} fullWidth multiline minRows={2}
            sx={{ "& textarea": { fontFamily: "monospace", fontSize: 11 } }}
            placeholder="-----BEGIN CERTIFICATE-----" />
          <FormControlLabel control={<Checkbox checked={form.insecureTls} onChange={(e) => set("insecureTls", e.target.checked)} />}
            label="Skip API-server TLS verification (test clusters only)" />
          <TextField label="Description" value={form.description} onChange={(e) => set("description", e.target.value)} fullWidth />
          {save.isError && <Alert severity="error">Could not save the cluster.</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending || !form.name.trim() || !form.apiServer.startsWith("https://")}
          onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}
