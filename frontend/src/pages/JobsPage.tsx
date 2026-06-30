import {
  Box, Chip, Paper, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, Typography, Tooltip,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { getJobs, type EnrollmentJob, type SchedulerStatus } from "../api/system";
import { formatDateTime, formatTime } from "../lib/datetime";

// Background jobs: scheduler heartbeats (cert renewal, approval expiry, host
// monitoring) and recent host-enrollment jobs. Auto-refreshes.
export function JobsPage() {
  const { data } = useQuery({ queryKey: ["jobs"], queryFn: getJobs, refetchInterval: 5000 });

  return (
    <Box>
      <Typography variant="h5" gutterBottom>Background Jobs</Typography>

      <Typography variant="h6" sx={{ mt: 2, mb: 1 }}>Schedulers</Typography>
      <TableContainer component={Paper} variant="outlined" sx={{ mb: 4 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Job</TableCell>
              <TableCell>State</TableCell>
              <TableCell>Runs</TableCell>
              <TableCell>Last run</TableCell>
              <TableCell>Last error</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(data?.schedulers ?? []).map((s: SchedulerStatus) => (
              <TableRow key={s.name} hover>
                <TableCell>{s.name}</TableCell>
                <TableCell>
                  <Chip size="small" label={s.ok ? "ok" : "error"} color={s.ok ? "success" : "error"} />
                </TableCell>
                <TableCell>{s.runs}</TableCell>
                <TableCell>{formatTime(s.lastRunAt)}</TableCell>
                <TableCell sx={{ color: "error.main" }}>{s.lastError || ""}</TableCell>
              </TableRow>
            ))}
            {data && data.schedulers.length === 0 && (
              <TableRow><TableCell colSpan={5}>No scheduler activity yet.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="h6" sx={{ mb: 1 }}>Enrollment jobs</Typography>
      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Target</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Steps</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Error</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {(data?.enrollmentJobs ?? []).map((j: EnrollmentJob) => (
              <TableRow key={j.id} hover>
                <TableCell>{j.target}</TableCell>
                <TableCell>
                  <Chip size="small" label={j.status} color={statusColor(j.status)} />
                </TableCell>
                <TableCell>
                  <Tooltip title={(j.steps ?? []).map((s) => `${s.status} ${s.name}`).join("\n")}>
                    <span>{(j.steps ?? []).filter((s) => s.status === "ok").length}/{(j.steps ?? []).length} ok</span>
                  </Tooltip>
                </TableCell>
                <TableCell>{formatDateTime(j.createdAt)}</TableCell>
                <TableCell sx={{ color: "error.main" }}>{j.error || ""}</TableCell>
              </TableRow>
            ))}
            {data && data.enrollmentJobs.length === 0 && (
              <TableRow><TableCell colSpan={5}>No enrollment jobs yet.</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

function statusColor(s: string): "success" | "error" | "warning" | "default" {
  if (s === "succeeded") return "success";
  if (s === "failed" || s === "rolled_back") return "error";
  if (s === "running" || s === "pending") return "warning";
  return "default";
}
