import { Alert, AlertTitle, Box, Chip, Stack, Typography } from "@mui/material";
import { useQuery } from "@tanstack/react-query";

import { hostBlastRadius } from "../api/hosts";

// What touching these hosts actually reaches.
//
// Hosts are selected as a flat list, and a selection of fifteen looks like
// fifteen independent machines right up until one of them turns out to be
// serving the other thirteen their root filesystems. This is the sentence that
// belongs BEFORE the confirm button, not in the post-mortem.
//
// Renders nothing at all when there is nothing to say. A preview that always
// occupies space trains people to scroll past it, and the one time it matters
// it will look like the times it did not.
export default function BlastRadiusWarning({ hostIds }: { hostIds: string[] }) {
  const { data, isPending, isError } = useQuery({
    queryKey: ["blast-radius", [...hostIds].sort()],
    queryFn: () => hostBlastRadius(hostIds),
    enabled: hostIds.length > 0,
    staleTime: 30_000,
  });

  // Silence while loading: a warning that appears a beat after the dialog would
  // arrive under a cursor already moving toward the confirm button.
  if (hostIds.length === 0 || isPending) return null;

  // A preview that could not run must not read as "nothing to worry about".
  if (isError) {
    return (
      <Alert severity="info" sx={{ mb: 2 }}>
        Could not check what else depends on these hosts. This is not a statement
        that nothing does.
      </Alert>
    );
  }

  const findings = data?.findings ?? [];
  if (findings.length === 0) return null;

  const worst = findings.some((f) => f.severity === "critical") ? "error" : "warning";

  return (
    <Alert severity={worst} sx={{ mb: 2 }}>
      <AlertTitle>
        {worst === "error" ? "This reaches hosts you have not selected" : "Order matters here"}
      </AlertTitle>
      <Stack spacing={1.5}>
        {findings.map((f) => (
          <Box key={`${f.hostId}:${f.kind}`}>
            <Typography variant="body2">{f.message}</Typography>
            <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mt: 0.5 }}>
              <Chip size="small" label={f.kind} />
              {f.dependents.slice(0, 12).map((d) => (
                <Chip key={d} size="small" variant="outlined" label={d} />
              ))}
              {f.dependents.length > 12 && (
                <Chip size="small" variant="outlined" label={`+${f.dependents.length - 12} more`} />
              )}
            </Stack>
          </Box>
        ))}
      </Stack>
    </Alert>
  );
}
