import { useState } from "react";
import { PickList } from "../components/PickList";
import {
  Alert, Box, Button, Chip, Paper, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, Tooltip, Typography, IconButton,
} from "@mui/material";
import BlockIcon from "@mui/icons-material/Block";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  getCARotation, listCAs, listCertificates, promoteCA, retireCA, revokeCertificate, rotateCA,
} from "../api/certificates";
import type { CACert, CARotationStatus, RevokeResult } from "../api/certificates";
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

  // A rotation is trusted first and signs second, so it spans minutes; poll while one
  // is pending so the page shows it finishing.
  const { data: rotation } = useQuery({
    queryKey: ["ca-rotation"], queryFn: getCARotation, enabled: canManage,
    refetchInterval: (q) => ((q.state.data as CARotationStatus | undefined)?.pendingId ? 30_000 : false),
  });
  const [caResult, setCaResult] = useState<{ ok: boolean; text: string } | null>(null);
  const caDone = (st: CARotationStatus) => {
    setCaResult({ ok: true, text: st.note ?? (st.promoted ? "The new key is signing." : "Done.") });
    void qc.invalidateQueries({ queryKey: ["cas"] });
    void qc.invalidateQueries({ queryKey: ["ca-rotation"] });
  };
  const caFailed = (e: unknown) => setCaResult({ ok: false,
    text: (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "That did not work." });
  const rotate = useMutation({ mutationFn: rotateCA, onSuccess: caDone, onError: caFailed });
  const promote = useMutation({ mutationFn: promoteCA, onSuccess: caDone, onError: caFailed });
  const retire = useMutation({ mutationFn: retireCA, onSuccess: caDone, onError: caFailed });
  const caState = (ca: CACert): { label: string; color: "success" | "info" | "warning" | "default" } => {
    if (!ca.active) return { label: "retired", color: "default" };
    if (ca.id === rotation?.signingId) return { label: "signing", color: "success" };
    if (!ca.signingSince) return { label: "pending — trusted, not signing yet", color: "info" };
    return { label: "trusted — no longer signing", color: "warning" };
  };
  const notConfirming = (rotation?.hosts ?? []).filter((h) => !h.inSync);
  // A revocation is only enforced on hosts that installed the updated KRL. Hosts
  // that did not still honor the certificate, so that count is surfaced as a
  // warning rather than left to the server log.
  const [revokeResult, setRevokeResult] = useState<RevokeResult | null>(null);
  const revoke = useMutation({
    mutationFn: (serial: number) => revokeCertificate(serial, "manually revoked"),
    onSuccess: (result) => {
      setRevokeResult(result);
      void qc.invalidateQueries({ queryKey: ["certs"] });
    },
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
            startIcon={<AutorenewIcon />} variant="outlined"
            onClick={() => { if (window.confirm(
              "Start a CA rotation?\n\nA new key is created and pushed to every host. It starts signing only once every " +
              "host and the jump host confirm they trust it — usually within five minutes. The current key keeps signing " +
              "until then, so nothing loses access. Afterwards, retire the old key here.")) rotate.mutate(); }}
            disabled={rotate.isPending || !!rotation?.pendingId}
          >
            {rotate.isPending ? "Rotating…" : rotation?.pendingId ? "Rotation in progress" : "Rotate CA"}
          </Button>
        )}
      </Stack>

      {caResult && (
        <Alert severity={caResult.ok ? "info" : "error"} sx={{ mb: 2 }} onClose={() => setCaResult(null)}>{caResult.text}</Alert>
      )}
      {rotation?.pendingId && (
        <Alert severity="info" sx={{ mb: 2 }}
          action={canManage && (
            <Stack direction="row" spacing={1}>
              <Button size="small" disabled={promote.isPending} onClick={() => promote.mutate(false)}>Check now</Button>
              {notConfirming.length > 0 && (
                <Button size="small" color="warning" disabled={promote.isPending}
                  onClick={() => { if (window.confirm(
                    `Promote the new key without these hosts?\n\n${notConfirming.map((h) => h.hostname).join(", ")}\n\n` +
                    "They will refuse new logins until they take the new key. Use this only for hosts that are gone for good.",
                  )) promote.mutate(true); }}>
                  Promote anyway
                </Button>
              )}
            </Stack>
          )}>
          Rotation in progress: {(rotation.hosts.length - rotation.outOfSync)} of {rotation.hosts.length} hosts
          confirm the new key{rotation.jumpTrustsPending === undefined ? "" :
            rotation.jumpTrustsPending ? ", and the jump host trusts it" : ", but the jump host does not yet"}.
          The current key keeps signing until everything trusts the new one; Provenance retries and promotes it by itself.
          {notConfirming.length > 0 && (
            <Box component="ul" sx={{ m: 0, mt: 0.5, pl: 2 }}>
              {notConfirming.map((h) => (
                <li key={h.hostId}>{h.hostname}{h.error ? ` — ${h.error}` : " — not yet confirmed"}</li>
              ))}
            </Box>
          )}
        </Alert>
      )}
      {!rotation?.pendingId && notConfirming.length > 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {notConfirming.length} host{notConfirming.length === 1 ? " does" : "s do"} not confirm the current CA keys:{" "}
          {notConfirming.map((h) => h.hostname).join(", ")}. Provenance retries every few minutes.
        </Alert>
      )}

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
              <TableCell />
            </TableRow>
          </TableHead>
          <TableBody>
            {(caData?.cas ?? []).map((ca) => (
              <TableRow key={ca.id} hover>
                <TableCell>{ca.kind}</TableCell>
                <TableCell>{ca.algo}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>{ca.fingerprint}</TableCell>
                <TableCell>
                  <Chip size="small" label={caState(ca).label} color={caState(ca).color} />
                </TableCell>
                <TableCell>{fmt(ca.createdAt)}</TableCell>
                <TableCell align="right">
                  {canManage && ca.active && ca.id !== rotation?.signingId && (
                    <Button size="small" color={ca.signingSince ? "warning" : "inherit"} disabled={retire.isPending}
                      onClick={() => { if (window.confirm(ca.signingSince
                        ? "Retire this key?\n\nHosts stop trusting it, so every certificate it signed stops working — " +
                          "including sessions started before the rotation, which will need to sign in again."
                        : "Abandon this rotation?\n\nThe new key is retired before it ever signs. The current key carries on.",
                      )) retire.mutate(ca.id); }}>
                      {ca.signingSince ? "Retire" : "Abandon rotation"}
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {caData && caData.cas.length === 0 && (
              <TableRow><TableCell colSpan={6}>No CA yet.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="h6" sx={{ mb: 1 }}>Issued certificates</Typography>
      {revokeResult && revokeResult.hostsFailed > 0 && (
        <Alert severity="warning" sx={{ mb: 1 }} onClose={() => setRevokeResult(null)}>
          Revoked, but {revokeResult.hostsFailed} of {revokeResult.hostsUpdated + revokeResult.hostsFailed} host
          {revokeResult.hostsUpdated + revokeResult.hostsFailed === 1 ? "" : "s"} did not install the updated
          revocation list and still accept this certificate. Check the backend log for the affected hosts, then
          re-run distribution or re-enroll them.
        </Alert>
      )}
      {revokeResult && revokeResult.hostsFailed === 0 && (
        <Alert severity="success" sx={{ mb: 1 }} onClose={() => setRevokeResult(null)}>
          Revoked and enforced on all {revokeResult.hostsUpdated} enrolled host
          {revokeResult.hostsUpdated === 1 ? "" : "s"}.
        </Alert>
      )}
      <Alert severity="info" sx={{ mb: 1 }}>
        Each browser login mints a unique, short-lived Ed25519 user certificate. Private keys
        live only in backend memory and are never stored.
      </Alert>
      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} alignItems={{ sm: "center" }} sx={{ mb: 2 }}>
        <PickList label="User" value={userFilter} onChange={setUserFilter}
                  anyLabel="All users" sx={{ minWidth: 200 }}
                  options={users.map((u) => ({ value: u, label: u }))} />
        <PickList label="Host" value={hostFilter} onChange={setHostFilter}
                  anyLabel="All hosts" sx={{ minWidth: 200 }}
                  options={hosts.map((hn) => ({ value: hn, label: hn }))} />
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
