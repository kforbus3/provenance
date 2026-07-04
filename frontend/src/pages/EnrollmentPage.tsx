import { useState } from "react";
import { formatDateTime } from "../lib/datetime";
import {
  Alert, Box, Button, Chip, Collapse, IconButton, List, ListItem, ListItemText, Paper,
  Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Typography,
} from "@mui/material";
import DeleteSweepIcon from "@mui/icons-material/DeleteSweep";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { clearEnrollmentJobs, listEnrollmentJobs, type EnrollmentJob } from "../api/enrollmentApi";

// Host enrollment history: every enrollment run with its per-step results, so
// you can review successes and diagnose failures. New hosts are enrolled from
// the Hosts page (the Enroll action on each host).
export function EnrollmentPage() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const { data: jobs = [], isLoading } = useQuery({
    queryKey: ["enrollment-jobs"], queryFn: () => listEnrollmentJobs(), refetchInterval: 5000,
  });
  const finishedCount = jobs.filter((j) => j.status !== "running").length;
  const clearMut = useMutation({
    mutationFn: clearEnrollmentJobs,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["enrollment-jobs"] }),
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" spacing={2} sx={{ mb: 1 }}>
        <Typography variant="h5" sx={{ flexGrow: 1 }}>Host Enrollment</Typography>
        <Button
          size="small" color="inherit" startIcon={<DeleteSweepIcon />}
          disabled={finishedCount === 0 || clearMut.isPending}
          onClick={() => {
            if (window.confirm(`Clear ${finishedCount} finished enrollment job(s)? Running jobs are kept.`)) {
              clearMut.mutate();
            }
          }}
        >
          {clearMut.isPending ? "Clearing…" : "Clear finished"}
        </Button>
      </Stack>
      <Alert severity="info" sx={{ mb: 2 }}>
        To enroll a host, go to <b
          style={{ cursor: "pointer", textDecoration: "underline" }}
          onClick={() => navigate("/hosts")}
        >Hosts</b> and click the Enroll (cable) action on the host. This page shows the history
        and status of enrollment runs.
      </Alert>

      <TableContainer component={Paper} variant="outlined">
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell />
              <TableCell>Target</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Steps</TableCell>
              <TableCell>Started</TableCell>
              <TableCell>Finished</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {jobs.map((j) => <JobRow key={j.id} job={j} />)}
            {!isLoading && jobs.length === 0 && (
              <TableRow><TableCell colSpan={6}>
                <Typography color="text.secondary">No enrollment runs yet.</Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </TableContainer>
    </Box>
  );
}

function JobRow({ job }: { job: EnrollmentJob }) {
  const [open, setOpen] = useState(false);
  const okCount = (job.steps ?? []).filter((s) => s.status === "ok").length;
  const fmt = (s?: string) => formatDateTime(s);
  return (
    <>
      <TableRow hover sx={{ cursor: "pointer" }} onClick={() => setOpen((o) => !o)}>
        <TableCell sx={{ width: 36 }}>
          <IconButton size="small">{open ? <KeyboardArrowDownIcon /> : <KeyboardArrowRightIcon />}</IconButton>
        </TableCell>
        <TableCell>{job.target}</TableCell>
        <TableCell><Chip size="small" label={job.status} color={statusColor(job.status)} /></TableCell>
        <TableCell>{okCount}/{(job.steps ?? []).length} ok</TableCell>
        <TableCell>{fmt(job.startedAt)}</TableCell>
        <TableCell>{fmt(job.finishedAt)}</TableCell>
      </TableRow>
      <TableRow>
        <TableCell colSpan={6} sx={{ py: 0, borderBottom: open ? undefined : "none" }}>
          <Collapse in={open} unmountOnExit>
            <Box sx={{ py: 1 }}>
              {job.error && <Alert severity="error" sx={{ mb: 1 }}>{job.error}</Alert>}
              <List dense>
                {(job.steps ?? []).map((s, i) => (
                  <ListItem key={i} disableGutters>
                    <ListItemText
                      primary={
                        <Stack direction="row" spacing={1} alignItems="center">
                          <Box sx={{ color: stepColor(s.status), width: 16 }}>{stepIcon(s.status)}</Box>
                          <span>{s.name}</span>
                        </Stack>
                      }
                      secondary={s.detail}
                    />
                  </ListItem>
                ))}
              </List>
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

function statusColor(s: string): "success" | "error" | "warning" | "default" {
  if (s === "succeeded") return "success";
  if (s === "failed" || s === "rolled_back") return "error";
  if (s === "running" || s === "pending") return "warning";
  return "default";
}
function stepColor(s: string): string {
  return s === "ok" ? "success.main" : s === "failed" ? "error.main" : s === "warning" ? "warning.main" : "text.secondary";
}
function stepIcon(s: string): string {
  return s === "ok" ? "✓" : s === "failed" ? "✗" : s === "warning" ? "⚠" : "•";
}
