import { useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import ContentCopyIcon from "@mui/icons-material/ContentCopy";
import TerminalIcon from "@mui/icons-material/Terminal";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import KeyIcon from "@mui/icons-material/VpnKey";
import {
  createJoinToken, listFederatedHosts, listSites, revokeSite, rotateHubKey,
  type FederationSite, type JoinTokenResult,
} from "../api/federation";
import { formatDateTime } from "../lib/datetime";

const LINK_COLOR: Record<string, "success" | "error" | "default"> = { up: "success", down: "error" };
const STATUS_COLOR: Record<string, "success" | "warning" | "error" | "default"> = {
  active: "success", pending: "warning", revoked: "error", error: "error",
};

// The hub's registry of federated sites: join new sites, watch their live link
// state, revoke, and see the aggregated host read-model across every site.
export function SitesPage() {
  const qc = useQueryClient();
  const { data: sites = [] } = useQuery({
    queryKey: ["fed-sites"],
    queryFn: listSites,
    refetchInterval: 5000, // link state changes; keep it fresh
  });
  const { data: hosts = [] } = useQuery({ queryKey: ["fed-hosts"], queryFn: () => listFederatedHosts() });
  const [adding, setAdding] = useState(false);

  const revoke = useMutation({
    mutationFn: (id: string) => revokeSite(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["fed-sites"] });
      void qc.invalidateQueries({ queryKey: ["fed-hosts"] });
    },
  });
  const rotate = useMutation({
    mutationFn: rotateHubKey,
    onSuccess: (r) => alert(`Hub key rotated.\nNew fingerprint: ${r.fingerprint}\nPushed to ${r.pushedToSites} linked site(s).`),
  });

  const hostName = (h: unknown): string => {
    const o = h as { hostname?: string } | null;
    return o?.hostname ?? "—";
  };
  const siteName = (id: string) => sites.find((s) => s.id === id)?.name ?? id.slice(0, 8);

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Federated Sites</Typography>
        <Button startIcon={<KeyIcon />} variant="outlined" disabled={rotate.isPending}
          onClick={() => {
            if (confirm("Rotate the hub federation key? The new key is pushed to all linked sites immediately; offline sites re-learn it when they reconnect."))
              rotate.mutate();
          }}>
          {rotate.isPending ? "Rotating…" : "Rotate hub key"}
        </Button>
        <Button startIcon={<AddIcon />} variant="contained" onClick={() => setAdding(true)}>Add Site</Button>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Each site is an independent Fleet Terminal instance on its own network that dials out to this
        hub. Manage them all from here.
      </Typography>

      <TableContainer component={Paper} variant="outlined" sx={{ mb: 4 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Site</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Link</TableCell>
              <TableCell>Last seen</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {sites.map((s: FederationSite) => (
              <TableRow key={s.id} hover>
                <TableCell>{s.name}</TableCell>
                <TableCell><Chip size="small" label={s.status} color={STATUS_COLOR[s.status] ?? "default"} /></TableCell>
                <TableCell><Chip size="small" label={s.linkState} color={LINK_COLOR[s.linkState] ?? "default"} /></TableCell>
                <TableCell sx={{ color: "text.secondary" }}>
                  {s.lastSeenAt ? formatDateTime(s.lastSeenAt) : "never"}
                </TableCell>
                <TableCell align="right">
                  <Tooltip title="Revoke & remove site">
                    <IconButton size="small" color="error"
                      onClick={() => { if (confirm(`Revoke site "${s.name}"? Its link is dropped and cached data removed.`)) revoke.mutate(s.id); }}>
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {sites.length === 0 && (
              <TableRow><TableCell colSpan={5} align="center" sx={{ color: "text.secondary", py: 4 }}>
                No sites joined yet. Click “Add Site” to generate a join token.
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="h6" sx={{ mb: 1 }}>Aggregated hosts ({hosts.length})</Typography>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Site</TableCell>
              <TableCell>Host</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Cached</TableCell>
              <TableCell align="right">Connect</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {hosts.map((h) => (
              <TableRow key={h.federatedId} hover>
                <TableCell>{siteName(h.siteId)}</TableCell>
                <TableCell>{hostName(h.host)}</TableCell>
                <TableCell>{h.status || "—"}</TableCell>
                <TableCell sx={{ color: "text.secondary" }}>{formatDateTime(h.cachedAt)}</TableCell>
                <TableCell align="right">
                  <Tooltip title="Open terminal (proxied through the hub)">
                    <IconButton size="small" color="primary"
                      onClick={() => window.open(`/sites/${h.siteId}/terminals/${h.hostId}`, "_blank", "noopener")}>
                      <TerminalIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
            {hosts.length === 0 && (
              <TableRow><TableCell colSpan={5} align="center" sx={{ color: "text.secondary", py: 3 }}>
                No hosts cached yet. They appear once a site links and pushes its inventory.
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      {adding && <AddSiteDialog onClose={() => { setAdding(false); void qc.invalidateQueries({ queryKey: ["fed-sites"] }); }} />}
    </Box>
  );
}

function AddSiteDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState("");
  const [result, setResult] = useState<JoinTokenResult | null>(null);
  const mint = useMutation({
    mutationFn: () => createJoinToken(name.trim(), 1),
    onSuccess: setResult,
  });

  const blob = result
    ? Object.entries(result.env).map(([k, v]) => `${k}=${v}`).join("\n")
    : "";

  return (
    <Dialog open fullWidth maxWidth="sm" onClose={onClose}>
      <DialogTitle>Add a site</DialogTitle>
      <DialogContent dividers>
        {!result ? (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Typography variant="body2" color="text.secondary">
              Name the new site, then paste the generated configuration into that site's environment.
              The join token is one-time and expires in 1 hour.
            </Typography>
            <TextField label="Site name" size="small" value={name} autoFocus fullWidth
              onChange={(e) => setName(e.target.value)} placeholder="e.g. datacenter-west" />
            {mint.error != null && <Alert severity="error">{(mint.error as Error).message}</Alert>}
          </Stack>
        ) : (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <Alert severity="success">
              Join token created. Set these on the new site and start it — it will dial back and appear
              above once linked. This token is shown only once.
            </Alert>
            <Box sx={{ position: "relative" }}>
              <TextField multiline fullWidth minRows={6} value={blob}
                InputProps={{ readOnly: true, sx: { fontFamily: "monospace", fontSize: 12 } }} />
              <Tooltip title="Copy">
                <IconButton size="small" sx={{ position: "absolute", top: 6, right: 6 }}
                  onClick={() => void navigator.clipboard?.writeText(blob)}>
                  <ContentCopyIcon fontSize="small" />
                </IconButton>
              </Tooltip>
            </Box>
            <Typography variant="caption" color="text.secondary">
              Hub key fingerprint: <code>{result.hubFingerprint}</code>
            </Typography>
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>{result ? "Done" : "Cancel"}</Button>
        {!result && (
          <Button variant="contained" disabled={!name.trim() || mint.isPending} onClick={() => mint.mutate()}>
            {mint.isPending ? "Creating…" : "Create join token"}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}
