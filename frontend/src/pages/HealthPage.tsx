import {
  Alert, Box, Chip, Paper, Stack, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Tooltip, Typography,
} from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import { useQuery } from "@tanstack/react-query";
import { getSystemHealth, type HealthComponent } from "../api/health";
import { formatDateTime } from "../lib/datetime";

const COLOR: Record<string, "success" | "warning" | "error" | "default"> = {
  ok: "success", warn: "warning", error: "error",
};

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
    </Box>
  );
}
