import { useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, MenuItem, Stack, TextField, Typography,
} from "@mui/material";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import {
  addHostDependency, listHostDependencies, removeHostDependency, listHosts,
  type HostDependencyKind,
} from "../api/hosts";

// The kinds, with what each one means when the thing below it goes away. The
// help text is the point: an operator recording "storage" should know it is the
// one whose failure does not look like itself.
const KINDS: { value: HostDependencyKind; label: string; help: string }[] = [
  { value: "hypervisor", label: "Hypervisor", help: "runs this host as a guest — it stops entirely when the hypervisor does" },
  { value: "storage", label: "Storage", help: "serves this host's disks — this host keeps answering the network while every write blocks" },
  { value: "network", label: "Network", help: "routes or resolves for this host" },
  { value: "other", label: "Other", help: "an application-level dependency worth recording" },
];

// Recording what a host stands on.
//
// This is the input side of topology: nothing warns about a dependency nobody
// wrote down. Both directions are shown, because they answer different
// questions — what to check before rebooting THIS host, and what to check
// before rebooting it for everyone else's sake.
export default function HostDependencies({ hostId }: { hostId: string }) {
  const qc = useQueryClient();
  const [dependsOnId, setDependsOnId] = useState<string>("");
  const [kind, setKind] = useState<HostDependencyKind>("storage");
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["host-dependencies", hostId],
    queryFn: () => listHostDependencies(hostId),
  });
  const { data: hosts } = useQuery({ queryKey: ["hosts", "all-for-deps"], queryFn: () => listHosts() });

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ["host-dependencies", hostId] });
    // The preview reads the same edges; leaving it cached would show a warning
    // that no longer matches what was just recorded.
    qc.invalidateQueries({ queryKey: ["blast-radius"] });
  };

  const add = useMutation({
    mutationFn: () => addHostDependency(hostId, dependsOnId, kind, note),
    onSuccess: () => { setDependsOnId(""); setNote(""); setError(null); invalidate(); },
    onError: (e: unknown) => {
      // A refused cycle names the path it found; show that rather than a generic
      // failure, because finding it by hand means walking a graph you cannot see.
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg || "Could not record that dependency.");
    },
  });

  const remove = useMutation({
    mutationFn: (v: { dependsOnId: string; kind: string }) =>
      removeHostDependency(hostId, v.dependsOnId, v.kind),
    onSuccess: invalidate,
  });

  const options = (hosts?.hosts ?? []).filter((h) => h.id !== hostId);
  const dependsOn = data?.dependsOn ?? [];
  const dependents = data?.dependents ?? [];

  return (
    <Box>
      <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Stands on</Typography>
      {dependsOn.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Nothing recorded. Until something is, no bulk action can warn about it.
        </Typography>
      ) : (
        <Stack spacing={0.5} sx={{ mb: 1 }}>
          {dependsOn.map((e) => (
            <Stack key={`${e.dependsOnId}:${e.kind}`} direction="row" spacing={1} alignItems="center">
              <Chip size="small" label={e.kind} />
              <Typography variant="body2">{e.dependsOn}</Typography>
              {e.note && (
                <Typography variant="caption" color="text.secondary">{e.note}</Typography>
              )}
              <Button
                size="small" color="inherit" startIcon={<DeleteOutlineIcon />}
                onClick={() => remove.mutate({ dependsOnId: e.dependsOnId, kind: e.kind })}
                disabled={remove.isPending}
              >
                Remove
              </Button>
            </Stack>
          ))}
        </Stack>
      )}

      {dependents.length > 0 && (
        <>
          <Typography variant="subtitle2" sx={{ mb: 0.5, mt: 1 }}>Carries</Typography>
          <Stack direction="row" spacing={0.5} flexWrap="wrap" useFlexGap sx={{ mb: 1 }}>
            {dependents.map((e) => (
              <Chip key={`${e.hostId}:${e.kind}`} size="small" variant="outlined"
                label={`${e.hostname} (${e.kind})`} />
            ))}
          </Stack>
        </>
      )}

      {error && <Alert severity="warning" sx={{ mb: 1 }} onClose={() => setError(null)}>{error}</Alert>}

      <Stack direction={{ xs: "column", sm: "row" }} spacing={1} alignItems="flex-start">
        <Autocomplete
          size="small" sx={{ minWidth: 200 }}
          options={options}
          getOptionLabel={(o) => o.hostname}
          value={options.find((o) => o.id === dependsOnId) ?? null}
          onChange={(_, v) => setDependsOnId(v?.id ?? "")}
          renderInput={(p) => <TextField {...p} label="Stands on" />}
        />
        <TextField
          select size="small" label="Kind" sx={{ minWidth: 150 }}
          value={kind} onChange={(e) => setKind(e.target.value as HostDependencyKind)}
          helperText={KINDS.find((k) => k.value === kind)?.help}
        >
          {KINDS.map((k) => <MenuItem key={k.value} value={k.value}>{k.label}</MenuItem>)}
        </TextField>
        <TextField
          size="small" label="Note (optional)" sx={{ minWidth: 180 }}
          value={note} onChange={(e) => setNote(e.target.value)}
        />
        <Button
          variant="outlined" size="small" sx={{ mt: 0.5 }}
          disabled={!dependsOnId || add.isPending}
          onClick={() => add.mutate()}
        >
          Add
        </Button>
      </Stack>
    </Box>
  );
}
