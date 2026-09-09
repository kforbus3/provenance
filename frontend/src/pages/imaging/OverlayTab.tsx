import { useRef, useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, IconButton,
  Paper, Stack, Table, TableBody, TableCell, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import DeleteIcon from "@mui/icons-material/Delete";
import RefreshIcon from "@mui/icons-material/Refresh";
import UploadFileIcon from "@mui/icons-material/UploadFile";
import DriveFolderUploadIcon from "@mui/icons-material/DriveFolderUpload";
import DownloadIcon from "@mui/icons-material/Download";
import DriveFileRenameOutlineIcon from "@mui/icons-material/DriveFileRenameOutline";
import LockOpenIcon from "@mui/icons-material/LockOpen";
import LinearProgress from "@mui/material/LinearProgress";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { saveBlob } from "../../lib/download";
import {
  listOverlay, readOverlayFile, writeOverlayFile, deleteOverlayFile,
  uploadOverlayFile, downloadOverlayFile, moveOverlayFile, chmodOverlayFile,
  readFileAsBase64,
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
  const [renaming, setRenaming] = useState<OverlayFile | null>(null);
  const [chmodding, setChmodding] = useState<OverlayFile | null>(null);
  const [upload, setUpload] = useState<{ done: number; total: number } | null>(null);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const dirInput = useRef<HTMLInputElement | null>(null);
  // Where uploads land. A file picked on its own has no path of its own, and a
  // folder brings only its own relative tree — neither knows where in the image
  // it belongs, so it is asked for once rather than per file.
  const [dest, setDest] = useState("/");

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

  const download = useMutation({
    mutationFn: (path: string) => downloadOverlayFile(path),
    onSuccess: (f) => {
      // Rebuilt from base64 so a binary comes back byte-identical; a text decode
      // here would have to guess an encoding and would corrupt anything that is
      // not what it guessed.
      const bin = atob(f.contentBase64);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      saveBlob(new Blob([bytes], { type: "application/octet-stream" }),
        f.path.split("/").pop() || "overlay-file");
    },
    onError: (e) => setMsg(errText(e, "Could not download that file."), "error"),
  });

  // Uploads run one at a time rather than all at once: the overlay is a directory
  // on one host and a hundred parallel writes to it buys nothing, while a serial
  // run gives an honest count and stops at the first refusal instead of leaving a
  // half-written tree with no indication of which half.
  async function uploadFiles(files: File[], keepTree: boolean) {
    if (files.length === 0) return;
    const base = dest.trim().replace(/\/+$/, "");
    setUpload({ done: 0, total: files.length });
    try {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const rel = keepTree
          ? (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name
          : f.name;
        const target = `${base || ""}/${rel}`.replace(/\/{2,}/g, "/");
        const b64 = await readFileAsBase64(f);
        await uploadOverlayFile(target, b64);
        setUpload({ done: i + 1, total: files.length });
      }
      setMsg(
        files.length === 1
          ? "Uploaded. It will be copied into the next image built."
          : `Uploaded ${files.length} files. They will be copied into the next image built.` +
            " A browser cannot read a file's permissions, so anything that has to run needs its mode set.",
      );
      refresh();
    } catch (e) {
      setMsg(errText(e, "Upload stopped."), "error");
      refresh();
    } finally {
      setUpload(null);
    }
  }

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
          size="small" startIcon={<AddIcon />} disabled={!canBuild}
          onClick={() => { setCreating(true); setEditing({ path: "/", size: 0, mode: "0644", executable: false, editable: true, content: "" }); }}
        >
          New file
        </Button>
        <Button
          size="small" startIcon={<UploadFileIcon />} disabled={!canBuild || !!upload}
          onClick={() => fileInput.current?.click()}
        >
          Upload files
        </Button>
        <Button
          size="small" variant="contained" startIcon={<DriveFolderUploadIcon />}
          disabled={!canBuild || !!upload}
          onClick={() => dirInput.current?.click()}
        >
          Upload folder
        </Button>
      </Stack>

      {canBuild && (
        <Stack direction="row" spacing={2} alignItems="center" sx={{ mb: 2 }}>
          <TextField
            size="small" label="Upload into" value={dest} onChange={(e) => setDest(e.target.value)}
            sx={{ minWidth: 340 }}
            InputProps={{ style: { fontFamily: "monospace" } }}
            helperText="Path in the image. A folder keeps its tree beneath this; files land in it directly."
          />
          <input
            ref={fileInput} type="file" multiple hidden
            onChange={(e) => {
              void uploadFiles(Array.from(e.target.files ?? []), false);
              e.target.value = "";
            }}
          />
          {/* webkitdirectory is how a browser offers a folder at all. It is not in
              React's typings, hence the cast — the attribute is what makes the
              picker return a tree rather than one file. */}
          <input
            ref={dirInput} type="file" hidden
            {...({ webkitdirectory: "", directory: "" } as Record<string, string>)}
            onChange={(e) => {
              void uploadFiles(Array.from(e.target.files ?? []), true);
              e.target.value = "";
            }}
          />
        </Stack>
      )}

      {upload && (
        <Box sx={{ mb: 2 }}>
          <Typography variant="caption" color="text.secondary">
            Uploading {upload.done} of {upload.total}…
          </Typography>
          <LinearProgress variant="determinate" value={(upload.done / upload.total) * 100} />
        </Box>
      )}

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
                  <Tooltip title="Download">
                    <span>
                      <IconButton size="small" disabled={download.isPending}
                                  onClick={() => download.mutate(f.path)}>
                        <DownloadIcon fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title="Rename or move">
                    <span>
                      <IconButton size="small" disabled={!canBuild} onClick={() => setRenaming(f)}>
                        <DriveFileRenameOutlineIcon fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title="Change mode">
                    <span>
                      <IconButton size="small" disabled={!canBuild} onClick={() => setChmodding(f)}>
                        <LockOpenIcon fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
                  <Tooltip title="Remove from the overlay">
                    <span>
                      <IconButton
                        size="small" disabled={!canBuild || remove.isPending}
                        onClick={() => remove.mutate(f.path)}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </span>
                  </Tooltip>
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

      {renaming && (
        <PathPrompt
          title="Rename or move"
          label="New path in the image"
          initial={renaming.path}
          confirm="Rename"
          onClose={() => setRenaming(null)}
          onSubmit={async (to) => {
            await moveOverlayFile(renaming.path, to);
            setRenaming(null);
            setMsg("Renamed.");
            refresh();
          }}
          setMsg={setMsg}
        />
      )}

      {chmodding && (
        <ModePrompt
          file={chmodding}
          onClose={() => setChmodding(null)}
          onSubmit={async (mode) => {
            await chmodOverlayFile(chmodding.path, mode);
            setChmodding(null);
            setMsg("Mode changed.");
            refresh();
          }}
          setMsg={setMsg}
        />
      )}

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

// PathPrompt asks for one path. Used for rename, which is a move within the
// overlay — the sidecar resolves both ends against the overlay root, so neither
// can name somewhere outside it.
function PathPrompt({ title, label, initial, confirm, onClose, onSubmit, setMsg }: {
  title: string;
  label: string;
  initial: string;
  confirm: string;
  onClose: () => void;
  onSubmit: (value: string) => Promise<void>;
  setMsg: (text: string, kind?: "success" | "error") => void;
}) {
  const [value, setValue] = useState(initial);
  const [busy, setBusy] = useState(false);
  const valid = value.startsWith("/") && value !== "/" && !value.endsWith("/");

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="sm">
      <DialogTitle>{title}</DialogTitle>
      <DialogContent>
        <TextField
          autoFocus fullWidth size="small" label={label} value={value} sx={{ mt: 1 }}
          onChange={(e) => setValue(e.target.value)}
          InputProps={{ style: { fontFamily: "monospace" } }}
          error={value !== "" && !valid}
          helperText={valid || value === ""
            ? "Absolute path, as it will exist on the machine."
            : "Must be an absolute path to a file."}
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained" disabled={!valid || busy}
          onClick={async () => {
            setBusy(true);
            try {
              await onSubmit(value.trim());
            } catch (e) {
              setMsg(errText(e, "That did not work."), "error");
            } finally {
              setBusy(false);
            }
          }}
        >
          {confirm}
        </Button>
      </DialogActions>
    </Dialog>
  );
}

// ModePrompt sets a file's permissions.
//
// It exists as its own step because a browser cannot read a file's mode when
// uploading it, so an uploaded folder of scripts arrives without its executable
// bits — and a script that lands unexecutable is a boot that quietly does nothing.
function ModePrompt({ file, onClose, onSubmit, setMsg }: {
  file: OverlayFile;
  onClose: () => void;
  onSubmit: (mode: number) => Promise<void>;
  setMsg: (text: string, kind?: "success" | "error") => void;
}) {
  const [mode, setMode] = useState(file.mode || "0644");
  const [busy, setBusy] = useState(false);
  const valid = /^[0-7]{3,4}$/.test(mode);

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle>Change mode</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 1 }}>
          <Typography variant="body2" color="text.secondary" sx={{ fontFamily: "monospace" }}>
            {file.path}
          </Typography>
          <TextField
            autoFocus size="small" label="Mode" value={mode} onChange={(e) => setMode(e.target.value)}
            error={!valid} InputProps={{ style: { fontFamily: "monospace" } }}
            helperText={valid ? "Octal. cp -a preserves it, so this is what lands on the machine."
                              : "Three or four octal digits, e.g. 0644."}
          />
          <Stack direction="row" spacing={1}>
            <Button size="small" onClick={() => setMode("0755")}>0755 — executable</Button>
            <Button size="small" onClick={() => setMode("0644")}>0644 — data</Button>
            <Button size="small" onClick={() => setMode("0600")}>0600 — private</Button>
          </Stack>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button
          variant="contained" disabled={!valid || busy}
          onClick={async () => {
            setBusy(true);
            try {
              await onSubmit(parseInt(mode, 8));
            } catch (e) {
              setMsg(errText(e, "Could not change the mode."), "error");
            } finally {
              setBusy(false);
            }
          }}
        >
          Set
        </Button>
      </DialogActions>
    </Dialog>
  );
}
