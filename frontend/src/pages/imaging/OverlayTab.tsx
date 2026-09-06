import { useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, IconButton,
  Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import RefreshIcon from "@mui/icons-material/Refresh";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listOverlay, readOverlayFile, writeOverlayFile, deleteOverlayFile,
  type OverlayContent, type OverlayFile,
} from "../../api/imaging";

// OverlayTab edits the files layered into an image at build time — unit files,
// configs, scripts.
//
// It is here rather than only on the build host because the person who decides
// what goes into an image is not always the person with a shell on the machine
// that builds it. The mode matters as much as the content: `cp -a` preserves it,
// so a script that lands without its executable bit is a boot that does nothing.

export function OverlayTab({ canBuild, setMsg }: {
  canBuild: boolean;
  setMsg: (text: string, kind?: "success" | "error") => void;
}) {
  const qc = useQueryClient();
  const { data, isLoading } = useQuery({ queryKey: ["imaging-overlay"], queryFn: listOverlay });
  const [editing, setEditing] = useState<OverlayContent | null>(null);
  const [creating, setCreating] = useState(false);

  const files = data?.files ?? [];
  const refresh = () => void qc.invalidateQueries({ queryKey: ["imaging-overlay"] });

  const open = useMutation({
    mutationFn: (path: string) => readOverlayFile(path),
    onSuccess: (f) => setEditing(f),
    onError: (e) => setMsg(errText(e, "Could not read that file."), "error"),
  });

  const remove = useMutation({
    mutationFn: (path: string) => deleteOverlayFile(path),
    onSuccess: () => { setMsg("File removed from the overlay."); refresh(); },
    onError: (e) => setMsg(errText(e, "Could not remove that file."), "error"),
  });

  return (
    <Box>
      <Stack direction="row" alignItems="center" sx={{ mb: 2 }}>
        <Box sx={{ flexGrow: 1 }}>
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>Overlay files</Typography>
          <Typography variant="body2" color="text.secondary">
            Copied into every image at build time, at the path shown. Changes apply to the
            next build — they do not touch machines already imaged.
            {data?.root ? <> Source: <code>{data.root}</code></> : null}
          </Typography>
        </Box>
        <Tooltip title="Refresh"><IconButton onClick={refresh}><RefreshIcon /></IconButton></Tooltip>
        <Button
          size="small" variant="contained" startIcon={<AddIcon />} disabled={!canBuild}
          onClick={() => { setCreating(true); setEditing({ path: "/", size: 0, mode: "0644", executable: false, editable: true, content: "" }); }}
        >
          New file
        </Button>
      </Stack>

      {!canBuild && (
        <Alert severity="info" sx={{ mb: 2 }}>
          Read-only — editing the overlay changes what every future image contains, so it
          needs the <code>Imaging.Build</code> permission.
        </Alert>
      )}

      <Paper variant="outlined" sx={{ overflowX: "auto" }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Path in the image</TableCell>
              <TableCell align="right">Size</TableCell>
              <TableCell>Mode</TableCell>
              <TableCell align="right" />
            </TableRow>
          </TableHead>
          <TableBody>
            {files.map((f: OverlayFile) => (
              <TableRow key={f.path} hover>
                <TableCell>
                  <Box
                    component="button"
                    onClick={() => { setCreating(false); open.mutate(f.path); }}
                    sx={{
                      background: "none", border: 0, p: 0, font: "inherit", color: "primary.main",
                      cursor: "pointer", fontFamily: "monospace", textAlign: "left",
                    }}
                  >
                    {f.path}
                  </Box>
                </TableCell>
                <TableCell align="right">{f.size.toLocaleString()} B</TableCell>
                <TableCell>
                  <Stack direction="row" spacing={0.5} alignItems="center">
                    <code>{f.mode}</code>
                    {f.executable && <Chip size="small" variant="outlined" label="executable" />}
                  </Stack>
                </TableCell>
                <TableCell align="right">
                  <IconButton
                    size="small" disabled={!canBuild || remove.isPending}
                    onClick={() => remove.mutate(f.path)}
                  >
                    <DeleteIcon fontSize="small" />
                  </IconButton>
                </TableCell>
              </TableRow>
            ))}
            {files.length === 0 && (
              <TableRow>
                <TableCell colSpan={4}>
                  <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                    {isLoading ? "Loading…" : "No overlay files — images are built from the base distribution alone."}
                  </Typography>
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {editing && (
        <OverlayEditor
          file={editing}
          creating={creating}
          onClose={() => { setEditing(null); setCreating(false); }}
          onSaved={() => { setEditing(null); setCreating(false); setMsg("Overlay file saved."); refresh(); }}
          setMsg={setMsg}
        />
      )}
    </Box>
  );
}

function OverlayEditor({ file, creating, onClose, onSaved, setMsg }: {
  file: OverlayContent;
  creating: boolean;
  onClose: () => void;
  onSaved: () => void;
  setMsg: (text: string, kind?: "success" | "error") => void;
}) {
  const [path, setPath] = useState(file.path);
  const [content, setContent] = useState(file.content ?? "");
  const [mode, setMode] = useState(file.mode || "0644");

  const save = useMutation({
    mutationFn: () => {
      // The mode is octal text in the UI because that is how anyone reading a
      // Dockerfile or a unit file writes it; parse it as octal, not decimal.
      const parsed = /^[0-7]{3,4}$/.test(mode) ? parseInt(mode, 8) : undefined;
      return writeOverlayFile(path, content, parsed);
    },
    onSuccess: onSaved,
    onError: (e) => setMsg(errText(e, "Could not save the file."), "error"),
  });

  const modeValid = /^[0-7]{3,4}$/.test(mode);

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="md">
      <DialogTitle>{creating ? "New overlay file" : file.path}</DialogTitle>
      <DialogContent>
        {!file.editable ? (
          <Alert severity="info">
            This file cannot be edited here — {file.reason || "it is not text"}. Replace it
            on the build host instead.
          </Alert>
        ) : (
          <Stack spacing={2} sx={{ mt: 1 }}>
            <TextField
              size="small" label="Path in the image" value={path}
              onChange={(e) => setPath(e.target.value)} disabled={!creating}
              placeholder="/etc/systemd/system/thing.service"
              InputProps={{ style: { fontFamily: "monospace" } }}
              helperText={creating ? "Absolute path, as it will exist on the machine." : " "}
            />
            <TextField
              size="small" label="Mode" value={mode} onChange={(e) => setMode(e.target.value)}
              error={!modeValid} sx={{ maxWidth: 160 }}
              InputProps={{ style: { fontFamily: "monospace" } }}
              helperText={modeValid
                ? "Octal. 0755 for anything that has to run."
                : "Three or four octal digits, e.g. 0644."}
            />
            <TextField
              multiline minRows={16} value={content} onChange={(e) => setContent(e.target.value)}
              InputProps={{ style: { fontFamily: "monospace", fontSize: 13 } }}
              spellCheck={false}
            />
          </Stack>
        )}
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained"
          disabled={!file.editable || save.isPending || !modeValid || !path.startsWith("/") || path === "/"}
          onClick={() => save.mutate()}
        >
          Save
        </Button>
      </DialogActions>
    </Dialog>
  );
}

function errText(e: unknown, fallback: string): string {
  const d = (e as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return d ? `${fallback} ${d}` : fallback;
}
