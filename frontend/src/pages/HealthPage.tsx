import {
  Alert, Box, Chip, Paper, Stack, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Tooltip, Typography,
} from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import type { ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";
import { getSystemHealth, type HealthComponent } from "../api/health";
import { getFipsReadiness, type FipsReadiness } from "../api/system";
import { formatDateTime } from "../lib/datetime";

const COLOR: Record<string, "success" | "warning" | "error" | "default"> = {
  ok: "success", warn: "warning", error: "error",
};

// A green OK / amber NOT-FIPS chip for a single readiness check.
function FipsChip({ ok, okLabel = "OK", badLabel = "NOT-FIPS" }: { ok: boolean; okLabel?: string; badLabel?: string }) {
  return <Chip size="small" label={ok ? okLabel : badLabel} color={ok ? "success" : "warning"} variant={ok ? "filled" : "outlined"} />;
}

function FipsRow({ label, value, ok }: { label: string; value: ReactNode; ok?: boolean }) {
  return (
    <Stack direction="row" alignItems="center" spacing={1} sx={{ py: 0.5 }}>
      <Typography variant="body2" sx={{ minWidth: 200, color: "text.secondary" }}>{label}</Typography>
      <Box sx={{ flexGrow: 1 }}>{value}</Box>
      {ok !== undefined && <FipsChip ok={ok} />}
    </Stack>
  );
}

// FIPS 140-3 readiness — mirrors `fleetctl fips check`. Advisory: shows whether each
// FIPS-critical artifact is on an approved algorithm so an operator can tell when it
// is safe to enable FLEET_FIPS_MODE. Hidden if the endpoint isn't available.
function FipsCard() {
  const { data, isError } = useQuery<FipsReadiness>({
    queryKey: ["system-fips"],
    queryFn: getFipsReadiness,
    refetchInterval: 30000,
    retry: false,
  });
  if (isError || !data) return null;

  return (
    <Paper variant="outlined" sx={{ p: 2, mt: 3 }}>
      <Stack direction="row" alignItems="center" spacing={1.5} sx={{ mb: 1 }}>
        <Typography variant="h6">FIPS 140-3 Readiness</Typography>
        <Chip
          size="small"
          label={data.ready ? "Core artifacts FIPS-approved" : "Not ready"}
          color={data.ready ? "success" : "warning"}
        />
      </Stack>
      <FipsRow label="FLEET_FIPS_MODE" value={<FipsChip ok={data.configFips} okLabel="on" badLabel="off" />} />
      <FipsRow label="Go FIPS module active" value={""} ok={data.moduleActive} />
      <FipsRow label="Overlay transport" value={data.overlay || "(unset)"} ok={data.overlayOk} />
      <FipsRow label="Active user CA key" value={data.caKeyAlgo || "(none)"} ok={data.caKeyOk} />
      <Box sx={{ py: 0.5 }}>
        <Typography variant="body2" sx={{ color: "text.secondary", mb: 0.5 }}>Password hashes</Typography>
        <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
          {data.passwords.length === 0 && <Typography variant="caption" color="text.secondary">none</Typography>}
          {data.passwords.map((p) => (
            <Chip key={p.algorithm} size="small" variant="outlined" color={p.fips ? "success" : "warning"}
              label={`${p.algorithm || "(none)"}: ${p.count}`} />
          ))}
        </Stack>
      </Box>
      <FipsRow label="MFA factors" value={`${data.totp} TOTP, ${data.webauthn} WebAuthn`} />
      {data.webauthn > 0 && (
        <Alert severity="info" sx={{ mt: 1 }}>
          WebAuthn passkeys registered before FIPS may use EdDSA, which FIPS forbids. Have those
          users re-register a passkey under FIPS (new registrations are restricted to ES256/RS256).
        </Alert>
      )}
      {!data.ready && (
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1 }}>
          Address the amber items above before enabling FIPS. See docs/fips-mode-plan.md for the
          migration steps (CA rotation, overlay, <code>fleetctl fips reseal-secrets</code>).
        </Typography>
      )}
    </Paper>
  );
}

// Admin System Health: a live status report of Fleet's subsystems. Auto-refreshes.
export function HealthPage() {
  const { data, isLoading, isFetching, refetch } = useQuery({
    queryKey: ["system-health"],
    queryFn: getSystemHealth,
    refetchInterval: 15000,
  });

  const overall = data?.overall ?? "ok";
  const banner =
    overall === "error" ? "One or more subsystems are failing."
    : overall === "warn" ? "Everything is running, with some warnings."
    : "All subsystems healthy.";

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>System Health</Typography>
        <Tooltip title="Refresh">
          <RefreshIcon
            sx={{ cursor: "pointer", opacity: isFetching ? 0.4 : 1 }}
            onClick={() => void refetch()}
          />
        </Tooltip>
      </Stack>

      {!isLoading && (
        <Alert severity={overall === "error" ? "error" : overall === "warn" ? "warning" : "success"} sx={{ mb: 2 }}>
          {banner}
          {data && (
            <Typography variant="caption" component="div" sx={{ mt: 0.5 }}>
              Checked {formatDateTime(data.checkedAt)} · version {data.version}
            </Typography>
          )}
        </Alert>
      )}

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Status</TableCell>
              <TableCell>Component</TableCell>
              <TableCell>Detail</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(data?.components ?? []).map((c: HealthComponent) => (
              <TableRow key={c.name} hover>
                <TableCell>
                  <Chip size="small" label={c.status} color={COLOR[c.status] ?? "default"} />
                </TableCell>
                <TableCell>{c.name}</TableCell>
                <TableCell sx={{ color: "text.secondary" }}>{c.detail}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <FipsCard />
    </Box>
  );
}
