import { useCallback, useEffect, useRef, useState } from "react";
import {
  Box, Breadcrumbs, Button, Divider, Drawer, IconButton, LinearProgress,
  Link, List, ListItemButton, ListItemIcon, ListItemText, Stack, Typography,
} from "@mui/material";
import CloseIcon from "@mui/icons-material/Close";
import FolderIcon from "@mui/icons-material/Folder";
import InsertDriveFileIcon from "@mui/icons-material/InsertDriveFile";
import DownloadIcon from "@mui/icons-material/Download";
import UploadIcon from "@mui/icons-material/Upload";
import RefreshIcon from "@mui/icons-material/Refresh";
import ArrowUpwardIcon from "@mui/icons-material/ArrowUpward";
import Guacamole from "guacamole-common-js";

interface Entry {
  streamName: string;
  label: string;
  isDir: boolean;
}

function basename(p: string): string {
  const parts = p.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : "/";
}

function parentOf(p: string): string {
  const parts = p.split("/").filter(Boolean);
  parts.pop();
  return "/" + parts.join("/");
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// RdpFilesDrawer browses, downloads from, and uploads to the redirected RDP drive
// exposed by guacd as a Guacamole.Object. Upload/download availability is enforced
// server-side (guacd disable-upload/disable-download); this UI simply surfaces them.
export function RdpFilesDrawer({
  fs, open, onClose,
}: {
  fs: Guacamole.Object;
  open: boolean;
  onClose: () => void;
}) {
  const [path, setPath] = useState("/");
  const [entries, setEntries] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const browse = useCallback((dir: string) => {
    setLoading(true);
    setError(null);
    fs.requestInputStream(dir, (stream: Guacamole.InputStream, mimetype: string) => {
      if (mimetype !== Guacamole.Object.STREAM_INDEX_MIMETYPE) {
        // Not a directory listing; ignore (shouldn't happen for a dir request).
        setLoading(false);
        return;
      }
      const reader = new Guacamole.JSONReader(stream);
      reader.onend = () => {
        const json = reader.getJSON() as Record<string, string>;
        const list: Entry[] = Object.entries(json).map(([streamName, mt]) => ({
          streamName,
          label: basename(streamName),
          isDir: mt === Guacamole.Object.STREAM_INDEX_MIMETYPE,
        }));
        list.sort((a, b) => (a.isDir === b.isDir ? a.label.localeCompare(b.label) : a.isDir ? -1 : 1));
        setEntries(list);
        setLoading(false);
      };
    });
  }, [fs]);

  useEffect(() => {
    if (open) browse(path);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const navigate = (dir: string) => { setPath(dir); browse(dir); };

  const download = (entry: Entry) => {
    setBusy(entry.label);
    fs.requestInputStream(entry.streamName, (stream: Guacamole.InputStream, mimetype: string) => {
      const reader = new Guacamole.BlobReader(stream, mimetype || "application/octet-stream");
      reader.onend = () => {
        triggerDownload(reader.getBlob(), entry.label);
        setBusy(null);
      };
    });
  };

  const onPickFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    const dest = (path === "/" ? "" : path) + "/" + file.name;
    setBusy(file.name);
    setError(null);
    const stream = fs.createOutputStream(file.type || "application/octet-stream", dest);
    const writer = new Guacamole.BlobWriter(stream);
    writer.oncomplete = () => { setBusy(null); browse(path); };
    writer.onerror = () => { setBusy(null); setError(`Upload of ${file.name} failed.`); };
    writer.sendBlob(file);
  };

  const crumbs = ["/", ...path.split("/").filter(Boolean).map((_, i, arr) => "/" + arr.slice(0, i + 1).join("/"))];

  return (
    <Drawer anchor="right" open={open} onClose={onClose}
      PaperProps={{ sx: { width: { xs: "100%", md: 460 }, p: 2 } }}>
      <Stack direction="row" alignItems="center" sx={{ mb: 1 }}>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>Files</Typography>
        <input ref={fileInputRef} type="file" hidden onChange={onPickFile} />
        <Button size="small" startIcon={<UploadIcon />} disabled={!!busy}
          onClick={() => fileInputRef.current?.click()}>Upload</Button>
        <IconButton size="small" onClick={() => browse(path)} disabled={loading}><RefreshIcon fontSize="small" /></IconButton>
        <IconButton onClick={onClose}><CloseIcon /></IconButton>
      </Stack>

      <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
        <IconButton size="small" disabled={path === "/"} onClick={() => navigate(parentOf(path))}>
          <ArrowUpwardIcon fontSize="small" />
        </IconButton>
        <Breadcrumbs sx={{ flexGrow: 1, fontSize: 13 }}>
          {crumbs.map((c) => (
            <Link key={c} component="button" underline="hover" color="inherit"
              onClick={() => navigate(c)}>{c === "/" ? "drive" : basename(c)}</Link>
          ))}
        </Breadcrumbs>
      </Stack>
      <Divider />

      {(loading || busy) && <LinearProgress sx={{ mt: 0.5 }} />}
      {busy && <Typography variant="caption" color="text.secondary">Transferring {busy}…</Typography>}
      {error && <Typography variant="caption" color="error">{error}</Typography>}

      <List dense sx={{ mt: 1 }}>
        {entries.map((entry) => (
          <ListItemButton
            key={entry.streamName}
            onClick={() => (entry.isDir ? navigate(entry.streamName) : download(entry))}
          >
            <ListItemIcon sx={{ minWidth: 36 }}>
              {entry.isDir ? <FolderIcon fontSize="small" color="primary" /> : <InsertDriveFileIcon fontSize="small" />}
            </ListItemIcon>
            <ListItemText primary={entry.label} />
            {!entry.isDir && <DownloadIcon fontSize="small" sx={{ color: "text.disabled" }} />}
          </ListItemButton>
        ))}
        {!loading && entries.length === 0 && (
          <Box sx={{ p: 2 }}>
            <Typography variant="body2" color="text.secondary">
              This folder is empty. Files copied into the Fleet drive inside the desktop appear here.
            </Typography>
          </Box>
        )}
      </List>
    </Drawer>
  );
}
