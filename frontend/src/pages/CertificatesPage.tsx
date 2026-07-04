import { useState } from "react";
import {
  Alert, Box, Button, Chip, MenuItem, Paper, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Tooltip, Typography, IconButton,
} from "@mui/material";
import BlockIcon from "@mui/icons-material/Block";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listCAs, listCertificates, revokeCertificate, rotateCA,
} from "../api/certificates";
import { useAuthStore } from "../store/auth";
import { formatDateTime } from "../lib/datetime";

// A certificate's key id encodes its owner and (for per-host certs) its target:
// "<user>/<session>/<serial>" or "<user>/host:<hostname>/<serial>". These derive
// the user/host for filtering without needing a names lookup.
const certUser = (keyId: string): string => keyId.split("/")[0] ?? "";
const certHost = (keyId: string): string => /(?:^|\/)host:([^/]+)/.exec(keyId)?.[1] ?? "";

// Certificate lifecycle: the internal SSH CA(s) and the ephemeral per-session
// certificates it has issued, with rotate (CA) and revoke (cert) actions.
export function CertificatesPage() {
  const qc = useQueryClient();
  const canManage = useAuthStore((s) => s.has("Certificate.Manage"));
  const { data: caData } = useQuery({ queryKey: ["cas"], queryFn: listCAs });
  const { data: certs = [] } = useQuery({ queryKey: ["certs"], queryFn: () => listCertificates() });

  const rotate = useMutation({
    mutationFn: rotateCA,
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["cas"] }); },
  });
  const revoke = useMutation({
    mutationFn: (serial: number) => revokeCertificate(serial, "manually revoked"),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["certs"] }); },
  });

  const fmt = (s?: string) => formatDateTime(s);
  const now = Date.now();

  const [userFilter, setUserFilter] = useState("");
  const [hostFilter, setHostFilter] = useState("");
  const users = Array.from(new Set(certs.map((c) => certUser(c.keyId)).filter(Boolean))).sort();
  const hosts = Array.from(new Set(certs.map((c) => certHost(c.keyId)).filter(Boolean))).sort();
  const filtered = certs.filter((c) =>
    (!userFilter || certUser(c.keyId) === userFilter) &&
    (!hostFilter || certHost(c.keyId) === hostFilter),
  );

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Certificate Management</Typography>
        {canManage && (
          <Button
            startIcon={<AutorenewIcon />} variant="outlined" disabled={rotate.isPending}
            onClick={() => { if (window.confirm("Rotate the user CA? New + existing CAs both stay trusted until the old one is retired.")) rotate.mutate(); }}
          >
            {rotate.isPending ? "Rotating…" : "Rotate CA"}
          </Button>
        )}
      </Stack>

      <Typography variant="h6" sx={{ mb: 1 }}>Certificate Authorities</Typography>
      <TableContainer component={Paper} variant="outlined" sx={{ mb: 4 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Kind</TableCell>
              <TableCell>Algorithm</TableCell>
              <TableCell>Fingerprint</TableCell>
              <TableCell>State</TableCell>
              <TableCell>Created</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(caData?.cas ?? []).map((ca) => (
              <TableRow key={ca.id} hover>
                <TableCell>{ca.kind}</TableCell>
                <TableCell>{ca.algo}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{ca.fingerprint}</TableCell>
                <TableCell>
                  <Chip size="small" label={ca.active ? "active" : "retired"} color={ca.active ? "success" : "default"} />
                </TableCell>
                <TableCell>{fmt(ca.createdAt)}</TableCell>
              </TableRow>
            ))}
            {caData && caData.cas.length === 0 && (
              <TableRow><TableCell colSpan={5}>No CA yet.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="h6" sx={{ mb: 1 }}>Issued certificates</Typography>
      <Alert severity="info" sx={{ mb: 1 }}>
        Each browser login mints a unique, short-lived Ed25519 user certificate. Private keys
        live only in backend memory and are never stored.
      </Alert>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }} sx={{ mb: 2 }}>
        <TextField
          select size="small" label="User" value={userFilter}
          onChange={(e) => setUserFilter(e.target.value)} sx={{ minWidth: 180 }}
        >
          <MenuItem value="">All users</MenuItem>
          {users.map((u) => <MenuItem key={u} value={u}>{u}</MenuItem>)}
        </TextField>
        <TextField
          select size="small" label="Host" value={hostFilter}
          onChange={(e) => setHostFilter(e.target.value)} sx={{ minWidth: 180 }}
        >
          <MenuItem value="">All hosts</MenuItem>
          {hosts.map((hn) => <MenuItem key={hn} value={hn}>{hn}</MenuItem>)}
        </TextField>
        <Box sx={{ flexGrow: 1 }} />
        <Typography variant="body2" color="text.secondary">{filtered.length} of {certs.length}</Typography>
      </Stack>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Serial</TableCell>
              <TableCell>Key ID</TableCell>
              <TableCell>Principals</TableCell>
              <TableCell>Issued</TableCell>
              <TableCell>Expires</TableCell>
              <TableCell>State</TableCell>
              {canManage && <TableCell align="right">Actions</TableCell>}
            </TableRow>
          </TableHead>
          <TableBody>
            {filtered.map((c) => {
              const expired = new Date(c.expiresAt).getTime() < now;
              const state = c.revokedAt ? "revoked" : expired ? "expired" : "valid";
              return (
                <TableRow key={c.id} hover>
                  <TableCell>{c.serial}</TableCell>
                  <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{c.keyId}</TableCell>
                  <TableCell>{(c.principals ?? []).join(", ")}</TableCell>
                  <TableCell>{fmt(c.issuedAt)}</TableCell>
                  <TableCell>{fmt(c.expiresAt)}</TableCell>
                  <TableCell>
                    <Chip size="small" label={state}
                      color={state === "valid" ? "success" : state === "revoked" ? "error" : "default"} />
                  </TableCell>
                  {canManage && (
                    <TableCell align="right">
                      {!c.revokedAt && !expired && (
                        <Tooltip title="Revoke">
                          <IconButton size="small" color="error" onClick={() => revoke.mutate(c.serial)}>
                            <BlockIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      )}
                    </TableCell>
                  )}
                </TableRow>
              );
            })}
            {filtered.length === 0 && (
              <TableRow><TableCell colSpan={canManage ? 7 : 6}>
                {certs.length === 0 ? "No certificates issued yet." : "No certificates match the filters."}
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
