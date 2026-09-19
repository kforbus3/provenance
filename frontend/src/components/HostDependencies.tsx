import { useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, MenuItem, Stack, TextField, Tooltip, Typography,
} from "@mui/material";
import DeleteOutlineIcon from "@mui/icons-material/DeleteOutline";
import CheckCircleOutlineIcon from "@mui/icons-material/CheckCircleOutline";
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

  // Accepting a suggestion is the same write as typing it in, with the evidence
  // kept as the note: what was observed at the moment it was recorded, which is
  // the one thing a person reading this edge in six months will want.
  const accept = useMutation({
    mutationFn: (v: { dependsOnId: string; kind: HostDependencyKind; evidence: string }) =>
      addHostDependency(hostId, v.dependsOnId, v.kind, `observed: ${v.evidence}`.slice(0, 200)),
    onSuccess: () => { setError(null); invalidate(); },
    onError: (e: unknown) => {
      const msg = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
      setError(msg || "Could not record that dependency.");
    },
  });

  const options = (hosts?.hosts ?? []).filter((h) => h.id !== hostId);
  const dependsOn = data?.dependsOn ?? [];
  const dependents = data?.dependents ?? [];
  const evidence = data?.evidence;
  const suggestions = evidence?.suggestions ?? [];
  const unmanaged = evidence?.unmanaged ?? [];
  const confirmedBy = new Map(
    (evidence?.confirmations ?? []).map((c) => [`${c.dependsOnId}:${c.kind}`, c.evidence]),
  );

  return (
    <Box>
      <Typography variant="subtitle2" sx={{ mb: 0.5 }}>Stands on</Typography>
      {dependsOn.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
          Nothing recorded. Until something is, no bulk action can warn about it.
          {suggestions.length > 0 && " Provenance can see some of it — below."}
        </Typography>
      ) : (
        <Stack spacing={0.5} sx={{ mb: 1 }}>
          {dependsOn.map((e) => (
            <Stack key={`${e.dependsOnId}:${e.kind}`} direction="row" spacing={1} alignItems="center">
              <Chip size="small" label={e.kind} />
              <Typography variant="body2">{e.dependsOn}</Typography>
              {confirmedBy.has(`${e.dependsOnId}:${e.kind}`) && (
                <Tooltip title={confirmedBy.get(`${e.dependsOnId}:${e.kind}`) ?? ""}>
                  <Chip
                    size="small" color="success" variant="outlined" icon={<CheckCircleOutlineIcon />}
                    label="seen on the host"
                  />
                </Tooltip>
              )}
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

      {suggestions.length > 0 && (
        <>
          <Typography variant="subtitle2" sx={{ mb: 0.5, mt: 1 }}>
            Provenance can see these, and nobody has recorded them
          </Typography>
          <Stack spacing={0.5} sx={{ mb: 1 }}>
            {suggestions.map((sg) => (
              <Stack key={`${sg.dependsOnId}:${sg.kind}`} direction="row" spacing={1} alignItems="center"
                     flexWrap="wrap" useFlexGap>
                <Chip size="small" label={sg.kind} />
                <Typography variant="body2">{sg.dependsOn}</Typography>
                <Typography variant="caption" color="text.secondary">{sg.evidence}</Typography>
                <Button size="small" variant="outlined" disabled={accept.isPending}
                        onClick={() => accept.mutate(sg)}>
                  Record it
                </Button>
              </Stack>
            ))}
          </Stack>
        </>
      )}

      {unmanaged.length > 0 && (
        <Alert severity="info" sx={{ mb: 1 }}>
          {unmanaged.map((u) => (
            <Typography key={u.server} variant="body2">
              This host depends on <b>{u.server}</b>, which Provenance does not manage — no
              dependency can be recorded for it, and nothing here will warn about it. ({u.evidence})
            </Typography>
          ))}
        </Alert>
      )}

      {evidence && !evidence.collected && (
        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
          This host has not reported its mounts yet, so nothing above could be checked against
          it. That is not the same as finding nothing.
        </Typography>
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
