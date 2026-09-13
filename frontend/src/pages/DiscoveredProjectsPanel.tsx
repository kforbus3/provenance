import {
  Alert, Box, Chip, Paper, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Tooltip, Typography,
} from "@mui/material";
import { useQuery } from "@tanstack/react-query";
import { listDiscoveredProjects } from "../api/stacks";

// Everything the fleet is running, whether or not Provenance manages it.
//
// The Stacks page used to list only ADOPTED stacks, and adoption happened as a
// side effect of a rollout that needed one — so a fresh deployment looked like an
// empty product with a setup task attached, when in fact every compose project
// was already discovered and most were already updatable.
//
// Nothing here needs configuring. A compose-managed container records its own
// project and directory, so these are found wherever they live: /home, /opt,
// /root, a Portainer volume. There is no convention to follow and nothing to tell
// Provenance.

export function DiscoveredProjectsPanel() {
  const { data: projects = [], isLoading, isError, error } = useQuery({
    queryKey: ["discovered-projects"],
    queryFn: listDiscoveredProjects,
  });

  if (isLoading) return <Typography variant="body2">Loading…</Typography>;

  // A failed request is not an empty fleet.
  //
  // This rendered "no compose projects found yet" — which reads as a fact about
  // the hosts — while the server was returning 500 on every call because the
  // query could not parse. The tab looked like a feature waiting for a sweep
  // that had already happened, for as long as the bug existed.
  if (isError) {
    return (
      <Alert severity="error">
        Could not list compose projects. {error instanceof Error ? error.message : ""}
      </Alert>
    );
  }

  if (projects.length === 0) {
    return (
      <Typography variant="body2" color="text.secondary">
        No compose projects found yet. They are discovered by the monitor sweep as
        it reaches each host — a host whose containers have only just become
        visible appears after its next sweep.
      </Typography>
    );
  }

  const adopted = projects.filter((p) => p.adopted).length;
  const byHost = new Set(projects.map((p) => p.hostname)).size;

  return (
    <Box>
      <Alert severity="info" sx={{ mb: 2 }}>
        <Typography variant="body2">
          <b>{projects.length} compose project{projects.length === 1 ? "" : "s"}</b>{" "}
          found across {byHost} host{byHost === 1 ? "" : "s"} — wherever they live.
          Nothing needs setting up: a compose-managed container records its own
          project and directory, so these are discovered by the ordinary monitor
          sweep.
          <Box component="div" sx={{ mt: 0.5 }}>
            <b>Updates work without adopting anything.</b> A rebuild — the same tag
            republished — is pulled and recreated in place. Provenance only needs a
            copy of the compose file to change a <em>version</em>, and it adopts one
            by itself when a rollout needs it.
          </Box>
        </Typography>
      </Alert>

      <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Host</TableCell>
              <TableCell>Project</TableCell>
              <TableCell>Location</TableCell>
              <TableCell>Containers</TableCell>
              <TableCell>Managed</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {projects.map((p) => (
              <TableRow key={`${p.hostId}-${p.project}-${p.dir}`} hover>
                <TableCell>{p.hostname}</TableCell>
                <TableCell>{p.project}</TableCell>
                <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>
                  {p.dir || <em>unknown</em>}
                </TableCell>
                <TableCell>
                  <Tooltip title={p.services.join(", ")}>
                    <span>{p.images}</span>
                  </Tooltip>
                </TableCell>
                <TableCell>
                  {p.adopted ? (
                    <Tooltip title="Provenance holds this compose file, so version changes are recorded as revisions with a rollback.">
                      <Chip label="adopted" size="small" color="success" variant="outlined" />
                    </Tooltip>
                  ) : (
                    <Tooltip title="Not held by Provenance — and it does not need to be. Rebuilds are applied in place; a version change adopts the file automatically at that point.">
                      <Chip label="updates in place" size="small" variant="outlined" />
                    </Tooltip>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1.5 }}>
        {adopted} of {projects.length} adopted. That number staying low is normal —
        a project is adopted only when a version change needs it.
      </Typography>
    </Box>
  );
}
