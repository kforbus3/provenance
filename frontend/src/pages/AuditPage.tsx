import { useState } from "react";
import { formatDateTime } from "../lib/datetime";
import {
  Alert, Box, Button, Chip, Paper, Stack, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Typography,
} from "@mui/material";
import VerifiedIcon from "@mui/icons-material/VerifiedUser";
import { useMutation, useQuery } from "@tanstack/react-query";
import { listAudit, verifyAudit, type AuditFilter, type VerifyResult } from "../api/audit";

// Render an audit event's detail map as compact, readable "key: value" pairs.
// Generic across every action; for approval decisions it surfaces the requester,
// the resource, and the decision (the approver/denier is the Actor column).
function DetailCell({ detail }: { detail?: Record<string, unknown> }) {
  if (!detail) return null;
  const parts = Object.entries(detail)
    .filter(([, v]) => v !== null && v !== undefined && v !== "")
    .map(([k, v]) => `${k}: ${typeof v === "object" ? JSON.stringify(v) : String(v)}`);
  if (parts.length === 0) return null;
  return (
    <Typography variant="caption" color="text.secondary">
      {parts.join(" · ")}
    </Typography>
  );
}

// Audit log viewer: a filterable table over the tamper-evident chain plus an
// integrity-verification action that reports whether the hash chain is intact.
export function AuditPage() {
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [filter, setFilter] = useState<AuditFilter>({ limit: 100 });

  const { data: events = [], isLoading } = useQuery({
    queryKey: ["audit", filter],
    queryFn: () => listAudit(filter),
  });

  const verifyMut = useMutation<VerifyResult>({ mutationFn: verifyAudit });

  const applyFilter = () => {
    setFilter({
      limit: 100,
      action: action || undefined,
      actor: actor || undefined,
    });
  };

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Audit Logs</Typography>
        <Button startIcon={<VerifiedIcon />} variant="outlined"
          disabled={verifyMut.isPending} onClick={() => verifyMut.mutate()}>
          Verify integrity
        </Button>
      </Stack>

      {verifyMut.data && (
        <Alert severity={verifyMut.data.intact ? "success" : "error"} sx={{ mb: 2 }}>
          {verifyMut.data.intact
            ? "Audit chain is intact."
            : `Audit chain broken at sequence ${verifyMut.data.brokenAtSeq}.`}
        </Alert>
      )}
      {verifyMut.isError && (
        <Alert severity="error" sx={{ mb: 2 }}>Could not verify the audit chain.</Alert>
      )}

      <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
        <TextField label="Action" size="small" value={action}
          onChange={(e) => setAction(e.target.value)} />
        <TextField label="Actor ID" size="small" value={actor}
          onChange={(e) => setActor(e.target.value)} />
        <Button variant="contained" onClick={applyFilter}>Filter</Button>
      </Stack>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Seq</TableCell>
              <TableCell>Time</TableCell>
              <TableCell>Actor</TableCell>
              <TableCell>Action</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>Details</TableCell>
              <TableCell>IP</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {events.map((ev) => (
              <TableRow key={ev.id} hover>
                <TableCell>{ev.seq}</TableCell>
                <TableCell>{formatDateTime(ev.createdAt)}</TableCell>
                <TableCell>{ev.actorName || ev.actorId || "system"}</TableCell>
                <TableCell><Chip label={ev.action} size="small" /></TableCell>
                <TableCell>{ev.targetKind ? `${ev.targetKind}:${ev.targetId ?? ""}` : ""}</TableCell>
                <TableCell><DetailCell detail={ev.detail} /></TableCell>
                <TableCell>{ev.ip}</TableCell>
              </TableRow>
            ))}
            {!isLoading && events.length === 0 && (
              <TableRow><TableCell colSpan={7}>
                <Typography color="text.secondary">No audit events match the filter.</Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}
