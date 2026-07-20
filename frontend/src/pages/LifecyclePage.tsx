import { Box, Chip, CircularProgress, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography, Button } from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import { useQuery } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { getLifecycleReport, type LifecycleItem } from "../api/lifecycle";

const STATUS_COLOR: Record<string, "error" | "warning" | "info" | "default"> = {
  expired: "error",
  expiring: "warning",
  stale: "info",
  aging: "default",
};

const KIND_LABEL: Record<LifecycleItem["kind"], string> = {
  api_token: "API token",
  credential: "Credential",
  password: "Password",
  ca_key: "CA key",
};

// Order rows most-urgent first so the top of the table is the work queue.
const STATUS_RANK: Record<string, number> = { expired: 0, expiring: 1, stale: 2, aging: 3 };

export function LifecyclePage() {
  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ["lifecycle"],
    queryFn: getLifecycleReport,
  });

  const items = [...(data?.items ?? [])].sort(
    (a, b) => (STATUS_RANK[a.status] ?? 9) - (STATUS_RANK[b.status] ?? 9) || b.ageDays - a.ageDays,
  );
  const counts = data?.counts ?? {};

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h5">Expiry &amp; Rotation</Typography>
        <Box sx={{ flexGrow: 1 }} />
        <Button size="small" startIcon={<RefreshIcon />} onClick={() => void refetch()} disabled={isFetching}>
          Refresh
        </Button>
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Credentials and keys that need lifecycle attention: API tokens expiring, expired, or unused;
        vault credentials overdue for rotation; aging user passwords; and aging CA keys. Metadata
        only — no secret material is shown.
      </Typography>

      <Stack direction="row" spacing={1} sx={{ mb: 2, flexWrap: "wrap", gap: 1 }}>
        <SummaryChip label="Expired" value={counts.expired} color="error" />
        <SummaryChip label="Expiring soon" value={counts.expiring} color="warning" />
        <SummaryChip label="Unused" value={counts.stale} color="info" />
        <SummaryChip label="Aging" value={counts.aging} color="default" />
      </Stack>

      {isLoading ? (
        <Box sx={{ display: "flex", justifyContent: "center", my: 4 }}><CircularProgress /></Box>
      ) : items.length === 0 ? (
        <Paper variant="outlined" sx={{ p: 3, textAlign: "center" }}>
          <Typography color="text.secondary">Nothing needs attention — all tokens, credentials, passwords, and CA keys are within their thresholds.</Typography>
        </Paper>
      ) : (
        <TableContainer component={Paper} variant="outlined">
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Type</TableCell>
                <TableCell>Name</TableCell>
                <TableCell>Context</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Detail</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {items.map((it) => (
                <TableRow key={`${it.kind}-${it.id}`} hover>
                  <TableCell>{KIND_LABEL[it.kind]}</TableCell>
                  <TableCell>{it.name}</TableCell>
                  <TableCell sx={{ color: "text.secondary" }}>{it.owner || "—"}</TableCell>
                  <TableCell>
                    <Chip size="small" label={it.status} color={STATUS_COLOR[it.status] ?? "default"} />
                  </TableCell>
                  <TableCell align="right">{detailText(it)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}

function SummaryChip({ label, value, color }: { label: string; value?: number; color: "error" | "warning" | "info" | "default" }) {
  const n = value ?? 0;
  return <Chip label={`${label}: ${n}`} color={n > 0 ? color : "default"} variant={n > 0 ? "filled" : "outlined"} />;
}

// detailText renders the actionable fact: for tokens, the expiry instant; for
// age-based items, how long overdue.
function detailText(it: LifecycleItem): string {
  if (it.kind === "api_token") {
    if (it.status === "expired" && it.dueAt) return `expired ${formatDateTime(it.dueAt)}`;
    if (it.status === "expiring" && it.dueAt) return `expires ${formatDateTime(it.dueAt)}`;
    return `unused ${it.ageDays}d`;
  }
  if (it.kind === "credential") return `not rotated in ${it.ageDays}d`;
  if (it.kind === "password") return `changed ${it.ageDays}d ago`;
  return `${it.ageDays}d old`;
}
