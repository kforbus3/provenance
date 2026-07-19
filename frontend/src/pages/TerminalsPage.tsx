import { useMemo, useState } from "react";
import {
  Autocomplete, Box, Button, Card, CardActions, CardContent, Chip, InputAdornment,
  MenuItem, Stack, TextField, Typography,
} from "@mui/material";
import SearchIcon from "@mui/icons-material/Search";
import TerminalIcon from "@mui/icons-material/Terminal";
import FolderIcon from "@mui/icons-material/Folder";
import DesktopWindowsIcon from "@mui/icons-material/DesktopWindows";
import { useQuery } from "@tanstack/react-query";
import { listHosts, type Host } from "../api/hosts";
import { WgDownChip, WgOnChip, wgDegraded, wgHealthy } from "../components/WgStatus";

const STATUS_COLOR: Record<string, "success" | "error" | "warning" | "default"> = {
  online: "success",
  offline: "error",
  unknown: "warning",
};

// Quick-connect launcher: the hosts a user can reach, each one click from an SSH
// terminal (or SFTP) in a new tab. This is the "see all my hosts and connect"
// view — distinct from the Hosts inventory, which is the full admin surface.
export function TerminalsPage() {
  const { data, isLoading } = useQuery({ queryKey: ["hosts"], queryFn: listHosts });
  const [q, setQ] = useState("");
  const [groups, setGroups] = useState<string[]>([]);
  const [status, setStatus] = useState("");

  // Group filter options come from the hosts themselves (the groups they belong
  // to), so it works without a groups API call and only lists relevant groups.
  const groupOptions = useMemo(
    () => Array.from(new Set((data?.hosts ?? []).flatMap((h) => h.groups ?? []))).sort(),
    [data],
  );

  const hosts = useMemo(() => {
    const all = data?.hosts ?? [];
    const needle = q.trim().toLowerCase();
    const matched = all.filter((h) => {
      if (needle && ![h.hostname, h.description, h.environment, ...(h.tags ?? [])]
        .join(" ").toLowerCase().includes(needle)) return false;
      if (groups.length && !(h.groups ?? []).some((g) => groups.includes(g))) return false;
      if (status && (h.status?.status ?? "unknown") !== status) return false;
      return true;
    });
    // Online first, then by hostname.
    return [...matched].sort((a, b) => {
      const rank = (h: Host) => (h.status?.status === "online" ? 0 : h.status?.status === "unknown" ? 1 : 2);
      return rank(a) - rank(b) || a.hostname.localeCompare(b.hostname);
    });
  }, [data, q, groups, status]);

  const openTerminal = (id: string) => window.open(`/terminals/${id}`, "_blank", "noopener");
  const openFiles = (id: string) => window.open(`/files/${id}`, "_blank", "noopener");
  const openDesktop = (id: string) => window.open(`/desktop/${id}`, "_blank", "noopener");

  return (
    <Box>
      <Typography variant="h5" gutterBottom>Terminals</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Connect to any host you have access to. Each session opens in its own tab
        with a unique, ephemeral SSH certificate.
      </Typography>

      <Stack direction={{ xs: "column", sm: "row" }} spacing={2} sx={{ mb: 2 }}>
        <TextField
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search hosts by name, environment, or tag…"
          size="small"
          sx={{ flexGrow: 1, maxWidth: 480 }}
          InputProps={{ startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment> }}
        />
        <TextField
          select size="small" label="Status" value={status}
          onChange={(e) => setStatus(e.target.value)} sx={{ minWidth: 150 }}
        >
          <MenuItem value="">All statuses</MenuItem>
          <MenuItem value="online">Online</MenuItem>
          <MenuItem value="offline">Offline</MenuItem>
          <MenuItem value="unknown">Unknown</MenuItem>
        </TextField>
        {groupOptions.length > 0 && (
          <Autocomplete
            multiple size="small" options={groupOptions} value={groups}
            onChange={(_, v) => setGroups(v)} sx={{ minWidth: 240 }}
            renderInput={(params) => <TextField {...params} label="Filter by group" />}
          />
        )}
      </Stack>

      {!isLoading && hosts.length === 0 && (
        <Typography color="text.secondary">
          {data?.hosts?.length ? "No hosts match your search." : "You don't have access to any hosts yet."}
        </Typography>
      )}

      <Box
        sx={{
          display: "grid",
          gap: 2,
          gridTemplateColumns: "repeat(auto-fill, minmax(280px, 1fr))",
        }}
      >
        {hosts.map((h) => {
          const status = h.status?.status ?? "unknown";
          return (
            <Card key={h.id} variant="outlined">
              <CardContent sx={{ pb: 1 }}>
                <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 0.5 }}>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, wordBreak: "break-all" }}>
                    {h.hostname}
                  </Typography>
                  <Stack direction="row" spacing={0.5} alignItems="center">
                    {wgDegraded(h) && <WgDownChip />}
                    {wgHealthy(h) && <WgOnChip />}
                    <Chip size="small" label={status} color={STATUS_COLOR[status] ?? "default"} />
                  </Stack>
                </Stack>
                <Typography variant="body2" color="text.secondary" noWrap>
                  {h.description || h.environment || h.address || "—"}
                </Typography>
                {h.status?.latencyMs != null && (
                  <Typography variant="caption" color="text.secondary">
                    {h.status.latencyMs} ms
                  </Typography>
                )}
              </CardContent>
              <CardActions>
                {h.protocol === "rdp" ? (
                  <Button
                    size="small" variant="contained" startIcon={<DesktopWindowsIcon />}
                    onClick={() => openDesktop(h.id)}
                  >
                    Desktop
                  </Button>
                ) : (
                  <>
                    <Button
                      size="small" variant="contained" startIcon={<TerminalIcon />}
                      onClick={() => openTerminal(h.id)}
                    >
                      Terminal
                    </Button>
                    <Button size="small" startIcon={<FolderIcon />} onClick={() => openFiles(h.id)}>
                      Files
                    </Button>
                  </>
                )}
              </CardActions>
            </Card>
          );
        })}
      </Box>
    </Box>
  );
}
