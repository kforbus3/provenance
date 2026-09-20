import { Alert, AlertTitle, Box, Chip, Collapse, Link, Stack, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { listUnhealthyContainers, type UnhealthyContainer } from "../api/stacks";

// Containers the fleet is not running properly, stated once at the top of the
// Containers page.
//
// It exists because of a gap that every individual piece of machinery was
// innocent of. Two containers were crash-looping in production -- one on a GPU
// host, one on a build host. The collector recorded them correctly, the API
// served them correctly, and the host detail panel drew an orange chip for each.
// The chip was inside a 220-pixel scrolling list on one host's expanded panel, so
// to see it you had to already suspect that host and go and look. Fleet-wide,
// there was no question that could be asked at all, and nobody asked it for days.
//
// So: not a new collector, not a new alert, no configuration. The same data,
// asked once, where somebody is already standing.
export function UnhealthyContainersBanner() {
  const [open, setOpen] = useState(false);
  const { data: bad = [] } = useQuery({
    queryKey: ["containers", "unhealthy"],
    queryFn: listUnhealthyContainers,
    // Cheap, and this is the kind of thing that should not need a reload to
    // appear. Aligned with the container collection rather than being chatty.
    refetchInterval: 60_000,
  });

  if (bad.length === 0) return null;

  // The staleness of the evidence, from the oldest collection among the rows.
  // Reported because a crash loop read from a three-day-old inventory is not
  // news, and a banner that does not say so sends somebody to fix a container
  // that has been fine since Tuesday.
  const oldest = bad
    .map((c) => c.collectedAt)
    .filter((t): t is string => Boolean(t))
    .sort()[0];
  const staleHours = oldest ? (Date.now() - new Date(oldest).getTime()) / 3_600_000 : 0;

  return (
    <Alert
      severity="warning"
      sx={{ mb: 2 }}
      action={
        <Link component="button" underline="hover" onClick={() => setOpen((v) => !v)} sx={{ mr: 1 }}>
          {open ? "Hide" : "Show"}
        </Link>
      }
    >
      <AlertTitle sx={{ mb: open ? 1 : 0 }}>
        {bad.length === 1
          ? "1 container is not running properly"
          : `${bad.length} containers are not running properly`}
        {staleHours > 24 && (
          <Typography component="span" variant="caption" color="text.secondary" sx={{ ml: 1 }}>
            (oldest reading is {Math.floor(staleHours / 24)} day
            {Math.floor(staleHours / 24) === 1 ? "" : "s"} old)
          </Typography>
        )}
      </AlertTitle>
      {/* unmountOnExit so the collapsed rows are genuinely absent rather than
          present at zero height. A test that asserts "not shown" against a
          mounted-but-invisible node passes for the wrong reason, and a screen
          reader reads what is in the DOM. */}
      <Collapse in={open} unmountOnExit>
        <Stack spacing={0.5} sx={{ mt: 0.5 }}>
          {bad.map((c) => (
            <Row key={`${c.hostId}:${c.name}`} c={c} />
          ))}
        </Stack>
      </Collapse>
    </Alert>
  );
}

function Row({ c }: { c: UnhealthyContainer }) {
  return (
    <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
      <Typography variant="body2" sx={{ fontFamily: "monospace", fontSize: 12, minWidth: 160 }}>
        {c.name}
      </Typography>
      <Chip label={c.hostname} size="small" variant="outlined" />
      <Typography variant="caption" color="text.secondary">
        {c.why}
      </Typography>
      {/* Docker's own line. The state is the category; this carries the detail --
          how long, and what it exited with. */}
      {c.status && (
        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: "monospace", fontSize: 11 }}>
          {c.status}
        </Typography>
      )}
      {/* Where it lives, so acting on it does not start with a search. */}
      {c.composeDir && (
        <Box component="span" sx={{ fontFamily: "monospace", fontSize: 11, color: "text.disabled" }}>
          {c.composeDir}
        </Box>
      )}
    </Stack>
  );
}
