import {
  Alert, Box, Button, Chip, Paper, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Tooltip, Typography, IconButton,
} from "@mui/material";
import BlockIcon from "@mui/icons-material/Block";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listCAs, listCertificates, revokeCertificate, rotateCA,
} from "../api/certificates";
import { useAuthStore } from "../store/auth";
import { formatDateTime } from "../lib/datetime";

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
            {certs.map((c) => {
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
            {certs.length === 0 && (
              <TableRow><TableCell colSpan={canManage ? 7 : 6}>No certificates issued yet.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
