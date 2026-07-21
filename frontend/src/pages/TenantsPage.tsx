import { useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle,
  IconButton, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import LoginIcon from "@mui/icons-material/Login";
import BlockIcon from "@mui/icons-material/Block";
import CheckCircleIcon from "@mui/icons-material/CheckCircle";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { listTenants, createTenant, setTenantStatus, type Tenant } from "../api/tenants";
import { useAuthStore } from "../store/auth";

// Provider console: create and administer customer tenants, and switch into one to
// operate within it. Only visible to provider-tenant admins in multi-tenant mode.
export function TenantsPage() {
  const qc = useQueryClient();
  const activeTenant = useAuthStore((s) => s.activeTenant);
  const ownTenant = useAuthStore((s) => s.tenantId);
  const switchTenant = useAuthStore((s) => s.switchTenant);
  const { data: tenants = [], isLoading, isError } = useQuery({ queryKey: ["tenants"], queryFn: listTenants });
  const [createOpen, setCreateOpen] = useState(false);
  const [name, setName] = useState("");
  const [err, setErr] = useState<string | null>(null);

  const create = useMutation({
    mutationFn: () => createTenant(name.trim()),
    onSuccess: () => { setCreateOpen(false); setName(""); setErr(null); void qc.invalidateQueries({ queryKey: ["tenants"] }); },
    onError: (e: unknown) => setErr((e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Could not create tenant."),
  });
  const status = useMutation({
    mutationFn: ({ id, s }: { id: string; s: "active" | "suspended" }) => setTenantStatus(id, s),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["tenants"] }),
  });

  // Switching context reloads the app's data for the newly-selected tenant.
  const enter = (id: string | null) => { switchTenant(id); void qc.invalidateQueries(); };

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Tenants</Typography>
        <Button variant="contained" onClick={() => setCreateOpen(true)}>New customer tenant</Button>
      </Stack>

      <Alert severity="info" sx={{ mb: 2 }}>
        Each customer tenant's hosts, users, sessions and data are fully isolated. As a provider
        admin you can <b>switch into</b> a tenant to operate within it — everything you then see and
        do is scoped to that tenant until you switch back to your own.
      </Alert>

      {activeTenant && (
        <Alert severity="warning" sx={{ mb: 2 }}
          action={<Button color="inherit" size="small" onClick={() => enter(null)}>Return to your tenant</Button>}>
          You are currently acting inside <b>{tenants.find((t) => t.id === activeTenant)?.name ?? activeTenant}</b>.
        </Alert>
      )}

      {isError && <Alert severity="error" sx={{ mb: 2 }}>Could not load tenants.</Alert>}

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell><TableCell>Slug</TableCell><TableCell>Kind</TableCell>
              <TableCell>Status</TableCell><TableCell align="right">Users</TableCell>
              <TableCell align="right">Hosts</TableCell><TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {tenants.map((t: Tenant) => {
              const here = t.id === (activeTenant ?? ownTenant);
              return (
                <TableRow key={t.id} hover selected={here}>
                  <TableCell>{t.name}{here && <Chip size="small" label="current" sx={{ ml: 1 }} />}</TableCell>
                  <TableCell sx={{ color: "text.secondary", fontFamily: "monospace" }}>{t.slug}</TableCell>
                  <TableCell><Chip size="small" label={t.kind} color={t.kind === "provider" ? "primary" : "default"} /></TableCell>
                  <TableCell><Chip size="small" label={t.status} color={t.status === "active" ? "success" : "warning"} /></TableCell>
                  <TableCell align="right">{t.userCount}</TableCell>
                  <TableCell align="right">{t.hostCount}</TableCell>
                  <TableCell align="right">
                    {t.kind === "customer" && (
                      <>
                        <Tooltip title={here ? "You are here" : "Switch into this tenant"}>
                          <span>
                            <IconButton size="small" disabled={here} onClick={() => enter(t.id)}><LoginIcon fontSize="small" /></IconButton>
                          </span>
                        </Tooltip>
                        {t.status === "active" ? (
                          <Tooltip title="Suspend">
                            <IconButton size="small" color="warning" onClick={() => status.mutate({ id: t.id, s: "suspended" })}><BlockIcon fontSize="small" /></IconButton>
                          </Tooltip>
                        ) : (
                          <Tooltip title="Re-activate">
                            <IconButton size="small" color="success" onClick={() => status.mutate({ id: t.id, s: "active" })}><CheckCircleIcon fontSize="small" /></IconButton>
                          </Tooltip>
                        )}
                      </>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
            {!isLoading && tenants.length === 0 && (
              <TableRow><TableCell colSpan={7} sx={{ textAlign: "center", color: "text.secondary" }}>No tenants.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)} fullWidth maxWidth="xs">
        <DialogTitle>New customer tenant</DialogTitle>
        <DialogContent>
          {err && <Alert severity="error" sx={{ mb: 1 }}>{err}</Alert>}
          <TextField
            autoFocus fullWidth label="Tenant name" value={name} sx={{ mt: 1 }}
            onChange={(e) => setName(e.target.value)} placeholder="Acme Corporation"
            helperText="A unique slug is generated from the name."
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateOpen(false)}>Cancel</Button>
          <Button variant="contained" disabled={name.trim().length < 2 || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? "Creating…" : "Create"}
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
}
