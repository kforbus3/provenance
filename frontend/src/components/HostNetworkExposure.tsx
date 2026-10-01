import { useState } from "react";
import { Alert, Box, Button, Chip, CircularProgress, Stack, Tooltip, Typography } from "@mui/material";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { hostNetScans, triggerNetScan, pathLabel } from "../api/netscan";
import { NetScanDialog, StatusChip } from "../pages/NetworkScansPage";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";

// HostNetworkExposure: this host's latest network scan on each path, from the host
// details dialog. The listening-ports section above it is what the host SAYS it has
// bound; this is what the network could actually reach.
export default function HostNetworkExposure({ hostId }: { hostId: string }) {
  const qc = useQueryClient();
  const canScan = useAuthStore((s) => s.has("Host.Scan"));
  const { data: scans = [], isLoading } = useQuery({
    queryKey: ["net-host", hostId], queryFn: () => hostNetScans(hostId), enabled: canScan,
  });
  const [open, setOpen] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ sev: "info" | "error"; text: string } | null>(null);
  const start = useMutation({
    mutationFn: () => triggerNetScan({ hostId }),
    onSuccess: (r) => {
      setMsg(r.skipped.length
        ? { sev: "info", text: `Not scanned: ${r.skipped[0].reason}` }
        : { sev: "info", text: "Network scan started — a full sweep takes a few minutes per address." });
      void qc.invalidateQueries({ queryKey: ["net-recent"] });
    },
    onError: (e) => setMsg({
      sev: "error",
      text: (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Could not start the scan.",
    }),
  });
  if (!canScan) return null;
  return (
    <Box sx={{ mt: 2 }}>
      <Stack direction="row" alignItems="center" spacing={1}>
        <Typography variant="overline" color="text.secondary" sx={{ flexGrow: 1 }}>Network exposure</Typography>
        <Button size="small" disabled={start.isPending} onClick={() => start.mutate()}>Network scan now</Button>
      </Stack>
      {msg && <Alert severity={msg.sev} sx={{ mb: 1, py: 0 }} onClose={() => setMsg(null)}>{msg.text}</Alert>}
      {isLoading && <CircularProgress size={16} />}
      {!isLoading && scans.length === 0 && (
        <Typography variant="body2" color="text.secondary">Not scanned from the network yet.</Typography>
      )}
      <Stack spacing={0.5}>
        {scans.map((s) => (
          <Stack key={s.id} direction="row" spacing={1} alignItems="center" sx={{ cursor: "pointer" }} onClick={() => setOpen(s.id)}>
            <Chip size="small" variant="outlined" label={pathLabel(s.path)} />
            <Typography variant="body2" sx={{ fontFamily: "monospace" }}>{s.target}</Typography>
            <StatusChip scan={s} />
            {s.status === "completed" && (
              <>
                <Typography variant="caption">{s.openPorts} open</Typography>
                {s.critical + s.high > 0 && <Chip size="small" color="error" label={`${s.critical + s.high} critical/high`} />}
                {s.medium + s.low > 0 && <Chip size="small" color="warning" variant="outlined" label={`${s.medium + s.low} medium/low`} />}
                {s.unexpected > 0 && (
                  <Tooltip title="Reachable ports the host's own listener list does not show.">
                    <Chip size="small" color="warning" label={`${s.unexpected} unexpected`} />
                  </Tooltip>
                )}
              </>
            )}
            <Typography variant="caption" color="text.secondary">{formatDateTime(s.finishedAt ?? s.createdAt)}</Typography>
          </Stack>
        ))}
      </Stack>
      {open && <NetScanDialog scanId={open} onClose={() => setOpen(null)} />}
    </Box>
  );
}
