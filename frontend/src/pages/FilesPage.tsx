import { useEffect, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useUIStore } from "../store/ui";
import {
  Alert, Box, Breadcrumbs, Button, Chip, IconButton, LinearProgress, Link, List,
  ListItem, ListItemButton, ListItemIcon, ListItemText, Paper, Stack, Typography,
} from "@mui/material";
import FolderIcon from "@mui/icons-material/Folder";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";
import DownloadIcon from "@mui/icons-material/Download";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import ArrowUpwardIcon from "@mui/icons-material/ArrowUpward";
import CloseIcon from "@mui/icons-material/Close";
import DriveFolderUploadIcon from "@mui/icons-material/DriveFolderUpload";
import ArrowBackIcon from "@mui/icons-material/ArrowBack";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { downloadDir, downloadFile, listDir, uploadFile } from "../api/sftp";
import { getHost } from "../api/hosts";
import { useDocumentTitle } from "../api/branding";

interface Transfer {
  id: string;
  name: string;
  dir: "up" | "down";
  loaded: number;
  total: number;
  status: "active" | "done" | "error" | "cancelled";
  controller: AbortController;
}

// SFTP file browser. All transfers are brokered by the backend through the SSH
// gateway and audited; the browser never speaks SFTP directly. Uploads stream
// from disk and downloads stream to disk (File System Access API) so large files
// never sit in memory; both show progress.
export function FilesPage() {
  // siteId is present for a federated host (reached through the hub). Setting the
  // site scope makes every SFTP call transparently proxy to that site.
  const { hostId, siteId } = useParams<{ hostId: string; siteId?: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const scope = useUIStore((s) => s.siteScope);
  const setSiteScope = useUIStore((s) => s.setSiteScope);
  useEffect(() => {
    if (siteId && scope !== siteId) setSiteScope(siteId);
  }, [siteId, scope, setSiteScope]);
  // Wait until the scope matches the route's site before firing SFTP calls, so
  // they proxy to the correct site instead of racing against the hub.
  const scopeReady = !siteId || scope === siteId;
  const [path, setPath] = useState(".");
  const [dragOver, setDragOver] = useState(false);
  const [transfers, setTransfers] = useState<Transfer[]>([]);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const folderInput = useRef<HTMLInputElement | null>(null);

  // webkitdirectory isn't a typed React prop; set it on the element directly.
  useEffect(() => {
    folderInput.current?.setAttribute("webkitdirectory", "");
    folderInput.current?.setAttribute("directory", "");
  }, []);

  const { data: host } = useQuery({
    queryKey: ["host", hostId, siteId],
    queryFn: () => getHost(hostId!),
    enabled: !!hostId && scopeReady,
  });
  useDocumentTitle(host?.hostname ? `Files · ${host.hostname}` : undefined);

  const { data, isLoading, error } = useQuery({
    queryKey: ["sftp", hostId, siteId, path],
    queryFn: () => listDir(hostId!, path),
    enabled: !!hostId && scopeReady,
  });

  const resolved = data?.path ?? path;

  const addTransfer = (name: string, dir: "up" | "down"): { id: string; controller: AbortController } => {
    const id = `${Date.now()}-${Math.round(Math.random() * 1e6)}`;
    const controller = new AbortController();
    setTransfers((t) => [{ id, name, dir, loaded: 0, total: 0, status: "active", controller }, ...t]);
    return { id, controller };
  };
  const update = (id: string, loaded: number, total: number) =>
    setTransfers((t) => t.map((x) => (x.id === id ? { ...x, loaded, total } : x)));
  const finish = (id: string, status: Transfer["status"]) => {
    setTransfers((t) => t.map((x) => (x.id === id ? { ...x, status } : x)));
    // Auto-dismiss successful transfers shortly after completion so the bar
    // doesn't linger; failures/cancellations stay until manually cleared.
    if (status === "done") {
      setTimeout(() => setTransfers((t) => t.filter((x) => x.id !== id)), 3500);
    }
  };
  const cancel = (t: Transfer) => {
    t.controller.abort();
    finish(t.id, "cancelled");
  };
  const aborted = (e: unknown) =>
    (e as { name?: string; code?: string })?.name === "CanceledError" ||
    (e as { name?: string })?.name === "AbortError";

  const startUpload = async (file: File, name: string) => {
    const { id, controller } = addTransfer(name, "up");
    try {
      await uploadFile(hostId!, resolved, file, name, (l, tot) => update(id, l, tot), controller.signal);
      finish(id, "done");
      void qc.invalidateQueries({ queryKey: ["sftp", hostId] });
    } catch (e) {
      finish(id, aborted(e) ? "cancelled" : "error");
    }
  };

  const startDownload = async (remote: string, name: string, isDir: boolean) => {
    const { id, controller } = addTransfer(isDir ? `${name}.tar` : name, "down");
    try {
      const fn = isDir ? downloadDir : downloadFile;
      await fn(hostId!, remote, (l, tot) => update(id, l, tot), controller.signal);
      finish(id, "done");
    } catch (e) {
      finish(id, aborted(e) ? "cancelled" : "error");
    }
  };

  const goUp = () => setPath(resolved.replace(/\/[^/]+\/?$/, "") || "/");
  const enter = (name: string) => setPath(resolved.replace(/\/$/, "") + "/" + name);

  const onFiles = (files: FileList | null) => {
    if (!files) return;
    // Folder uploads carry a relative subpath; the backend recreates the tree.
    Array.from(files).forEach((f) => void startUpload(f, f.webkitRelativePath || f.name));
  };

  return (
    <Box
      sx={{ p: 3, minHeight: "100vh" }}
      onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => { e.preventDefault(); setDragOver(false); onFiles(e.dataTransfer.files); }}
    >
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 2 }}>
        <Stack direction="row" spacing={1.5} alignItems="center">
          <Button startIcon={<ArrowBackIcon />} onClick={() => navigate("/hosts")} size="small" variant="outlined">
            Hosts
          </Button>
          <Typography variant="h5">Files{host?.hostname ? ` · ${host.hostname}` : ""}</Typography>
        </Stack>
        <Stack direction="row" spacing={1}>
          <Button startIcon={<ArrowUpwardIcon />} onClick={goUp} size="small">Up</Button>
          <Button
            startIcon={<UploadFileIcon />} variant="contained" size="small"
            onClick={() => fileInput.current?.click()}
          >
            Upload files
          </Button>
          <Button
            startIcon={<DriveFolderUploadIcon />} variant="outlined" size="small"
            onClick={() => folderInput.current?.click()}
          >
            Upload folder
          </Button>
          <input
            ref={fileInput} type="file" multiple hidden
            onChange={(e) => { onFiles(e.target.files); e.target.value = ""; }}
          />
          <input
            ref={folderInput} type="file" multiple hidden
            onChange={(e) => { onFiles(e.target.files); e.target.value = ""; }}
          />
        </Stack>
      </Stack>

      <Breadcrumbs sx={{ mb: 1 }}>
        <Link component="button" onClick={() => setPath("/")}>/</Link>
        <Typography color="text.primary">{resolved}</Typography>
      </Breadcrumbs>

      {error && <Alert severity="error">{(error as Error).message}</Alert>}

      {transfers.length > 0 && (
        <Paper variant="outlined" sx={{ p: 1.5, mb: 2 }}>
          <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
            <Typography variant="subtitle2" sx={{ flexGrow: 1 }}>Transfers</Typography>
            <IconButton size="small" onClick={() => setTransfers((t) => t.filter((x) => x.status === "active"))}>
              <CloseIcon fontSize="small" />
            </IconButton>
          </Stack>
          <Stack spacing={1}>
            {transfers.map((t) => {
              const pct = t.total > 0 ? Math.round((t.loaded / t.total) * 100) : 0;
              // All bytes sent but the server is still committing (writing the
              // remote file / responding) — show this instead of a stuck 100%.
              const finalizing = t.status === "active" && t.total > 0 && t.loaded >= t.total;
              return (
                <Box key={t.id}>
                  <Stack direction="row" spacing={1} alignItems="center">
                    <Chip size="small" label={t.dir === "up" ? "↑" : "↓"} />
                    <Typography variant="body2" sx={{ flexGrow: 1 }} noWrap>{t.name}</Typography>
                    <Typography variant="caption" color="text.secondary">
                      {finalizing
                        ? "finalizing…"
                        : t.status === "active"
                          ? `${formatBytes(t.loaded)}${t.total ? " / " + formatBytes(t.total) : ""}${t.total ? ` (${pct}%)` : ""}`
                          : t.status}
                    </Typography>
                    {t.status === "active" && !finalizing && (
                      <IconButton size="small" onClick={() => cancel(t)} title="Cancel">
                        <CloseIcon fontSize="small" />
                      </IconButton>
                    )}
                  </Stack>
                  <LinearProgress
                    variant={finalizing || (t.status === "active" && t.total === 0) ? "indeterminate" : "determinate"}
                    value={t.status === "done" ? 100 : pct}
                    color={t.status === "error" ? "error" : t.status === "done" ? "success" : "primary"}
                    sx={{ mt: 0.5, height: 6, borderRadius: 3 }}
                  />
                </Box>
              );
            })}
          </Stack>
        </Paper>
      )}

      <Paper
        variant="outlined"
        sx={{ borderStyle: dragOver ? "dashed" : "solid", borderColor: dragOver ? "primary.main" : undefined }}
      >
        <List dense>
          {isLoading && <ListItem><ListItemText primary="Loading…" /></ListItem>}
          {data?.entries.map((e) => (
            <ListItem
              key={e.name}
              secondaryAction={
                <IconButton
                  edge="end"
                  title={e.isDir ? "Download folder as .tar" : "Download"}
                  onClick={() =>
                    void startDownload(resolved.replace(/\/$/, "") + "/" + e.name, e.name, e.isDir)
                  }
                >
                  <DownloadIcon />
                </IconButton>
              }
              disablePadding
            >
              <ListItemButton onClick={() => e.isDir && enter(e.name)} disabled={!e.isDir}>
                <ListItemIcon sx={{ minWidth: 36 }}>
                  {e.isDir ? <FolderIcon color="primary" /> : <InsertDriveFileIcon />}
                </ListItemIcon>
                <ListItemText
                  primary={e.name}
                  secondary={`${e.mode}  ${e.isDir ? "" : formatBytes(e.size)}`}
                />
              </ListItemButton>
            </ListItem>
          ))}
          {data && data.entries.length === 0 && (
            <ListItem><ListItemText primary="(empty directory)" /></ListItem>
          )}
        </List>
      </Paper>
      <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: "block" }}>
        Drag files here to upload, or use “Upload folder” for whole directories. Folders download
        as a .tar archive. All transfers are audited and can be cancelled.
      </Typography>
    </Box>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(1)} ${units[i]}`;
}
