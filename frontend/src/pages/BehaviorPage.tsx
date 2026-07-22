import {
  Box, Card, CardContent, Chip, CircularProgress, Stack, Typography,
} from "@mui/material";
import ScheduleIcon from "@mui/icons-material/Schedule";
import DnsIcon from "@mui/icons-material/Dns";
import LanIcon from "@mui/icons-material/Lan";
import TrendingUpIcon from "@mui/icons-material/TrendingUp";
import InsightsIcon from "@mui/icons-material/Insights";
import { useQuery } from "@tanstack/react-query";
import { getAnomalies, type Anomaly } from "../api/ueba";
import { formatDateTime } from "../lib/datetime";

const ICON: Record<string, React.ReactNode> = {
  off_hours: <ScheduleIcon />, new_host: <DnsIcon />, new_source_ip: <LanIcon />, activity_spike: <TrendingUpIcon />,
};

// BehaviorPage surfaces access-pattern anomalies from behavior analytics (UEBA):
// deviations from each user's established baseline. Advisory — verify before acting.
export function BehaviorPage() {
  const { data, isLoading } = useQuery({ queryKey: ["ueba-anomalies"], queryFn: getAnomalies, refetchInterval: 300_000 });
  const anomalies = data?.anomalies ?? [];
  const warnings = anomalies.filter((a) => a.severity === "warning");

  return (
    <Box sx={{ maxWidth: 1000 }}>
      <Typography variant="h5">Behavior analytics</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Access patterns that deviate from each user's established baseline — off-hours access, first
        access to a host, a new source IP, or an activity spike. Advisory signals from your own session
        records; verify before acting.
      </Typography>

      {isLoading ? (
        <Stack alignItems="center" sx={{ py: 6 }}><CircularProgress /></Stack>
      ) : (
        <>
          <Stack direction="row" spacing={2} sx={{ mb: 2 }} color="text.secondary">
            <Typography variant="body2">{data?.analyzed ?? 0} sessions analyzed (last {data?.lookbackDays}d)</Typography>
            <Typography variant="body2">·</Typography>
            <Typography variant="body2">{warnings.length} warning{warnings.length === 1 ? "" : "s"}, {anomalies.length - warnings.length} informational</Typography>
          </Stack>

          {anomalies.length === 0 ? (
            <Card variant="outlined">
              <CardContent>
                <Stack alignItems="center" spacing={1} sx={{ py: 4 }} color="text.secondary">
                  <InsightsIcon fontSize="large" />
                  <Typography>No anomalies in the recent window. Access is consistent with established baselines.</Typography>
                </Stack>
              </CardContent>
            </Card>
          ) : (
            <Stack spacing={1.5}>
              {anomalies.map((a, i) => <AnomalyCard key={i} a={a} />)}
            </Stack>
          )}
        </>
      )}
    </Box>
  );
}

function AnomalyCard({ a }: { a: Anomaly }) {
  const color = a.severity === "warning" ? "warning.main" : "info.main";
  return (
    <Card variant="outlined" sx={{ borderLeft: 4, borderLeftColor: color }}>
      <CardContent sx={{ py: 1.5, "&:last-child": { pb: 1.5 } }}>
        <Stack direction="row" spacing={1.5} alignItems="flex-start">
          <Box sx={{ color, mt: 0.3 }}>{ICON[a.type] ?? <InsightsIcon />}</Box>
          <Box sx={{ flexGrow: 1 }}>
            <Stack direction="row" spacing={1} alignItems="center">
              <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>{a.title}</Typography>
              <Chip size="small" label={a.severity} color={a.severity === "warning" ? "warning" : "info"} variant="outlined" />
              {a.host && <Chip size="small" variant="outlined" label={a.host} />}
            </Stack>
            <Typography variant="body2" color="text.secondary">{a.detail}</Typography>
          </Box>
          <Typography variant="caption" color="text.secondary" sx={{ whiteSpace: "nowrap" }}>{formatDateTime(a.when)}</Typography>
        </Stack>
      </CardContent>
    </Card>
  );
}
