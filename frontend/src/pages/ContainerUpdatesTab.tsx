import { useMemo, useState } from "react";
import {
  Alert, Box, Button, Chip, Collapse, IconButton, Paper, Snackbar, Stack, Table,
  TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip,
  Typography,
} from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listContainerUpdates, checkContainerUpdates, type ImageUpdate,
} from "../api/containerUpdates";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";

// Available container image updates.
//
// This is the half a renovate bot did — ask the registry what exists — without
// the half that opened merge requests nobody read. The answer lands next to the
// hosts it is true of, so deciding and acting are the same screen.

const errMsg = (e: unknown, fallback: string) =>
  (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? fallback;

// What this row is telling the operator, as one of four states. Kept in one
// place because the states overlap: an image can have a newer tag AND a moved
// digest, and showing both as separate badges reads as two problems.
type Verdict = "error" | "newer" | "moved" | "current" | "unknown";

function verdictOf(u: ImageUpdate): Verdict {
  if (u.error) return "error";
  if (u.latestTag) return "newer";
  if (u.hosts.some((h) => h.stale)) return "moved";
  // A note with no newer tag means the registry answered but its tags could not
  // be ordered confidently. That is NOT "up to date" — saying so would be a
  // guess presented as a fact.
  if (u.note && !u.latestTag) return "unknown";
  return "current";
}

function VerdictChip({ u }: { u: ImageUpdate }) {
  switch (verdictOf(u)) {
    case "error":
      return (
        <Tooltip title={u.error ?? ""}>
          <Chip label="could not check" size="small" color="default" variant="outlined" />
        </Tooltip>
      );
    case "newer":
      return <Chip label={`${u.latestTag} available`} size="small" color="warning" />;
    case "moved":
      return (
        <Tooltip title="The tag points at different bytes than these hosts are running — usually a rebuild of the same version.">
          <Chip label="rebuilt" size="small" color="info" />
        </Tooltip>
      );
    case "unknown":
      return (
        <Tooltip title={u.note ?? ""}>
          <Chip label="cannot compare" size="small" variant="outlined" />
        </Tooltip>
      );
    default:
      return <Chip label="up to date" size="small" color="success" variant="outlined" />;
  }
}

function UpdateRow({ u }: { u: ImageUpdate }) {
  const [open, setOpen] = useState(false);
  const stale = u.hosts.filter((h) => h.stale).length;
  return (
    <>
      <TableRow hover>
        <TableCell sx={{ width: 40 }}>
          <IconButton size="small" onClick={() => setOpen((o) => !o)}>
            {open ? <KeyboardArrowDownIcon fontSize="small" /> : <KeyboardArrowRightIcon fontSize="small" />}
          </IconButton>
        </TableCell>
        <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>
          {u.repository}:{u.tag}
        </TableCell>
        <TableCell><VerdictChip u={u} /></TableCell>
        <TableCell>
          {u.hosts.length}
          {stale > 0 && (
            <Typography component="span" variant="caption" color="text.secondary">
              {" "}({stale} behind)
            </Typography>
          )}
        </TableCell>
        <TableCell>{formatDateTime(u.checkedAt)}</TableCell>
      </TableRow>
      <TableRow>
        <TableCell sx={{ py: 0, borderBottom: open ? undefined : "none" }} colSpan={5}>
          <Collapse in={open} unmountOnExit>
            <Box sx={{ py: 1.5, pl: 5 }}>
              {(u.note || u.error) && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {u.error || u.note}
                </Typography>
              )}
              {u.digest && (
                <Typography variant="caption" color="text.secondary"
                            sx={{ fontFamily: "monospace", display: "block", mb: 1 }}>
                  registry: {u.digest.slice(0, 19)}…
                </Typography>
              )}
              {u.hosts.length === 0 && (
                <Typography variant="body2" color="text.secondary">
                  No host currently reports running this image.
                </Typography>
              )}
              {u.hosts.map((h) => (
                <Stack key={`${h.hostId}-${h.container}`} direction="row" spacing={1}
                       alignItems="center" sx={{ mb: 0.5 }}>
                  <Typography variant="body2" sx={{ minWidth: 160 }}>{h.hostname}</Typography>
                  {h.container && (
                    <Typography variant="caption" color="text.secondary"
                                sx={{ fontFamily: "monospace" }}>{h.container}</Typography>
                  )}
                  {h.stale
                    ? <Chip label="running older bytes" size="small" color="warning" variant="outlined" />
                    : h.digest
                      ? <Chip label="matches registry" size="small" variant="outlined" />
                      : <Chip label="digest unknown" size="small" variant="outlined" />}
                </Stack>
              ))}
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

export function ContainerUpdatesTab() {
  const qc = useQueryClient();
  const canScan = useAuthStore((s) => s.has("Host.Scan"));
  const [filter, setFilter] = useState("");
  const [snack, setSnack] = useState("");

  const { data: updates = [], isLoading } = useQuery({
    queryKey: ["container-updates"],
    queryFn: listContainerUpdates,
    placeholderData: keepPreviousData,
  });

  const check = useMutation({
    mutationFn: checkContainerUpdates,
    onSuccess: (r) => setSnack(r.note || "Checking registries…"),
    onError: (e) => setSnack(errMsg(e, "Could not start a check.")),
  });

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    const rows = q
      ? updates.filter((u) =>
          `${u.repository}:${u.tag}`.toLowerCase().includes(q) ||
          u.hosts.some((h) => h.hostname.toLowerCase().includes(q)))
      : updates;
    // Actionable first. An operator opening this screen wants the images that
    // need a decision, not an alphabetical list with three of them buried in it.
    const rank: Record<Verdict, number> = { newer: 0, moved: 1, unknown: 2, error: 3, current: 4 };
    return [...rows].sort((a, b) =>
      rank[verdictOf(a)] - rank[verdictOf(b)] ||
      a.repository.localeCompare(b.repository));
  }, [updates, filter]);

  const actionable = updates.filter((u) => {
    const v = verdictOf(u);
    return v === "newer" || v === "moved";
  }).length;

  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        What the registries say is available for the images your hosts are running.
        Checked twice a day; a newer version tag and a rebuilt tag are reported
        separately, because a rebuild keeps the same version number.
      </Typography>

      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
        <TextField size="small" placeholder="Filter by image or host"
                   value={filter} onChange={(e) => setFilter(e.target.value)}
                   sx={{ maxWidth: 320, flex: 1 }} />
        {canScan && (
          <Button startIcon={<RefreshIcon />} disabled={check.isPending}
                  onClick={() => check.mutate()}>Check now</Button>
        )}
        <Button size="small" onClick={() => qc.invalidateQueries({ queryKey: ["container-updates"] })}>
          Refresh
        </Button>
      </Stack>

      {actionable > 0 && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          {actionable} image{actionable > 1 ? "s have" : " has"} something newer available.
        </Alert>
      )}

      {isLoading && <Typography variant="body2">Loading…</Typography>}
      {!isLoading && updates.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          Nothing checked yet. Container lists are collected on the monitor sweep, and
          registries are asked shortly after — or press “Check now”.
        </Typography>
      )}

      {shown.length > 0 && (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell />
                <TableCell>Image</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Hosts</TableCell>
                <TableCell>Checked</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {shown.map((u) => <UpdateRow key={`${u.repository}:${u.tag}`} u={u} />)}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <Snackbar open={!!snack} autoHideDuration={6000} onClose={() => setSnack("")}
                message={snack} />
    </Box>
  );
}
