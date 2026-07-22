import { useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogTitle, IconButton,
  MenuItem, Paper, Stack, Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TextField, Tooltip, Typography,
} from "@mui/material";
import AddIcon from "@mui/icons-material/Add";
import EditIcon from "@mui/icons-material/Edit";
import DeleteIcon from "@mui/icons-material/Delete";
import PlayArrowIcon from "@mui/icons-material/PlayArrow";
import StorageIcon from "@mui/icons-material/Storage";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "../store/auth";
import {
  listDatabases, createDatabase, updateDatabase, deleteDatabase, runQuery,
  type Database, type DatabaseInput, type QueryResult,
} from "../api/databases";
import { listVaultSecrets } from "../api/vault";

// Per-engine connection defaults, mirrored from the backend (internal/dbbroker/engines.go).
const ENGINE_DEFAULT_PORT: Record<string, number> = { postgres: 5432, mysql: 3306, mariadb: 3306, sqlserver: 1433, mongodb: 27017 };
const ENGINE_DEFAULT_DB: Record<string, string> = { postgres: "postgres", mysql: "", mariadb: "", sqlserver: "master", mongodb: "admin" };
const isDocEngine = (engine: string) => engine === "mongodb";

// DatabasesPage: register database targets and run brokered SQL — Fleet reaches the
// database through the jump host with a vaulted credential injected, and audits every
// query, so the operator never sees the password.
export function DatabasesPage() {
  const qc = useQueryClient();
  const has = useAuthStore((s) => s.has);
  const canManage = has("Database.Manage");
  const canConnect = has("Database.Connect");
  const { data: databases = [], isLoading } = useQuery({ queryKey: ["databases"], queryFn: listDatabases });
  const [editing, setEditing] = useState<Database | null>(null);
  const [creating, setCreating] = useState(false);
  const [console_, setConsole] = useState<Database | null>(null);
  const invalidate = () => qc.invalidateQueries({ queryKey: ["databases"] });
  const del = useMutation({ mutationFn: (id: string) => deleteDatabase(id), onSuccess: invalidate });

  return (
    <Box sx={{ maxWidth: 1150 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Box>
          <Typography variant="h5">Databases</Typography>
          <Typography variant="body2" color="text.secondary">
            Run SQL against registered databases through the jump host with a vaulted credential —
            you never see the password, and every query is audited.
          </Typography>
        </Box>
        {canManage && <Button variant="contained" startIcon={<AddIcon />} onClick={() => setCreating(true)}>Register database</Button>}
      </Stack>

      <Paper variant="outlined" sx={{ mb: 2 }}>
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Name</TableCell>
              <TableCell>Engine</TableCell>
              <TableCell>Target</TableCell>
              <TableCell>Database</TableCell>
              <TableCell>Credential</TableCell>
              <TableCell align="right">Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {databases.map((d) => (
              <TableRow key={d.id} hover>
                <TableCell>{d.name}</TableCell>
                <TableCell><Chip size="small" variant="outlined" label={d.engine} /></TableCell>
                <TableCell>{d.address}:{d.port}</TableCell>
                <TableCell>{d.databaseName}</TableCell>
                <TableCell>{d.credentialName || <Typography variant="caption" color="warning.main">none</Typography>}</TableCell>
                <TableCell align="right">
                  {canConnect && (
                    <Tooltip title="Open SQL console"><span><IconButton size="small" color="primary"
                      disabled={!d.credentialId} onClick={() => setConsole(d)}>
                      <PlayArrowIcon fontSize="small" /></IconButton></span></Tooltip>
                  )}
                  {canManage && <>
                    <Tooltip title="Edit"><IconButton size="small" onClick={() => setEditing(d)}><EditIcon fontSize="small" /></IconButton></Tooltip>
                    <Tooltip title="Delete"><IconButton size="small" color="error"
                      onClick={() => { if (window.confirm(`Delete database "${d.name}"?`)) del.mutate(d.id); }}>
                      <DeleteIcon fontSize="small" /></IconButton></Tooltip>
                  </>}
                </TableCell>
              </TableRow>
            ))}
            {databases.length === 0 && (
              <TableRow><TableCell colSpan={6}>
                <Typography variant="body2" color="text.secondary" sx={{ py: 1 }}>
                  {isLoading ? "Loading…" : canManage ? "No databases registered yet." : "No databases available."}
                </Typography>
              </TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </Paper>

      {console_ && <QueryConsole db={console_} onClose={() => setConsole(null)} />}

      {creating && <DatabaseDialog onClose={() => setCreating(false)} onSaved={() => { setCreating(false); invalidate(); }} />}
      {editing && <DatabaseDialog db={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); invalidate(); }} />}
    </Box>
  );
}

// QueryConsole runs SQL against one database and renders the result grid.
function QueryConsole({ db, onClose }: { db: Database; onClose: () => void }) {
  const doc = isDocEngine(db.engine);
  const [sql, setSql] = useState(
    doc
      ? '{ "listCollections": 1 }'
      : db.engine === "sqlserver"
        ? "SELECT TOP 20 * FROM information_schema.tables;"
        : "SELECT * FROM information_schema.tables LIMIT 20;",
  );
  const [result, setResult] = useState<QueryResult | null>(null);
  const run = useMutation({
    mutationFn: () => runQuery(db.id, sql),
    onSuccess: (r) => setResult(r),
  });
  const errMsg = (run.error as { response?: { data?: { error?: string } } })?.response?.data?.error;
  return (
    <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
      <Stack direction="row" alignItems="center" justifyContent="space-between" sx={{ mb: 1 }}>
        <Stack direction="row" spacing={1} alignItems="center">
          <StorageIcon color="primary" fontSize="small" />
          <Typography variant="subtitle1" sx={{ fontWeight: 600 }}>
            {doc ? "Command console" : "SQL console"} — {db.name}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            {db.address}:{db.port}/{db.databaseName} · as {db.credentialName}
          </Typography>
        </Stack>
        <Button size="small" onClick={onClose}>Close</Button>
      </Stack>
      <TextField
        multiline minRows={3} fullWidth value={sql} onChange={(e) => setSql(e.target.value)}
        placeholder={doc ? '{ "find": "collection", "limit": 5 }' : "SELECT ..."} spellCheck={false}
        label={doc ? "MongoDB command (JSON)" : undefined}
        sx={{ mb: 1, "& textarea": { fontFamily: "monospace", fontSize: 13 } }}
      />
      {doc && <Typography variant="caption" color="text.secondary" sx={{ display: "block", mb: 1 }}>
        Enter a MongoDB command document, e.g. <code>{'{ "listCollections": 1 }'}</code> or <code>{'{ "find": "users", "limit": 10 }'}</code>.
      </Typography>}
      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
        <Button variant="contained" size="small" startIcon={<PlayArrowIcon />}
          disabled={run.isPending || !sql.trim()} onClick={() => run.mutate()}>
          {run.isPending ? "Running…" : "Run"}
        </Button>
        {result && !run.isError && (
          <Typography variant="caption" color="text.secondary">
            {result.command || `${result.rowCount} row(s)`}{result.truncated ? ` · truncated to first ${result.rows.length}` : ""}
          </Typography>
        )}
      </Stack>
      {run.isError && <Alert severity="error" sx={{ mb: 1 }}>{errMsg || "Query failed."}</Alert>}
      {result && result.document && (
        <Box component="pre" sx={{
          m: 0, p: 1.5, maxHeight: 460, overflow: "auto", border: 1, borderColor: "divider", borderRadius: 1,
          fontFamily: "monospace", fontSize: 12.5, bgcolor: "action.hover", whiteSpace: "pre-wrap", wordBreak: "break-word",
        }}>{result.document}</Box>
      )}
      {result && !result.document && result.columns.length > 0 && (
        <TableContainer sx={{ maxHeight: 420, border: 1, borderColor: "divider", borderRadius: 1 }}>
          <Table size="small" stickyHeader>
            <TableHead>
              <TableRow>{result.columns.map((c, i) => <TableCell key={i} sx={{ fontWeight: 600 }}>{c}</TableCell>)}</TableRow>
            </TableHead>
            <TableBody>
              {result.rows.map((row, ri) => (
                <TableRow key={ri} hover>
                  {row.map((cell, ci) => (
                    <TableCell key={ci} sx={{ fontFamily: "monospace", fontSize: 12, whiteSpace: "pre", maxWidth: 340, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {cell}
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {result && !result.document && result.columns.length === 0 && !run.isError && (
        <Typography variant="body2" color="text.secondary">{result.command || "Statement executed."}</Typography>
      )}
    </Paper>
  );
}

// DatabaseDialog registers or edits a database target, with a credential picker from
// the vault (password credentials only).
function DatabaseDialog({ db, onClose, onSaved }: { db?: Database; onClose: () => void; onSaved: () => void }) {
  const [form, setForm] = useState<DatabaseInput>({
    name: db?.name ?? "", engine: "postgres", address: db?.address ?? "", port: db?.port ?? 5432,
    databaseName: db?.databaseName ?? "postgres", credentialId: db?.credentialId ?? null, description: db?.description ?? "",
  });
  const { data: secrets = [] } = useQuery({ queryKey: ["vault-secrets"], queryFn: listVaultSecrets });
  const passwordSecrets = secrets.filter((s) => s.type === "password");
  const save = useMutation({
    mutationFn: () => db ? updateDatabase(db.id, form) : createDatabase(form),
    onSuccess: onSaved,
  });
  const set = (k: keyof DatabaseInput, v: string | number | null) => setForm((f) => ({ ...f, [k]: v }));
  // Switching engine (on a new registration) snaps the port to that engine's default
  // so the operator doesn't have to remember 5432 / 3306 / 1433.
  const onEngineChange = (engine: string) => {
    setForm((f) => {
      const next = { ...f, engine };
      if (!db && (f.port === ENGINE_DEFAULT_PORT[f.engine] || !f.port)) {
        next.port = ENGINE_DEFAULT_PORT[engine] ?? f.port;
      }
      if (!db && (f.databaseName === ENGINE_DEFAULT_DB[f.engine] || !f.databaseName)) {
        next.databaseName = ENGINE_DEFAULT_DB[engine] ?? f.databaseName;
      }
      return next;
    });
  };
  return (
    <Dialog open onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{db ? "Edit database" : "Register database"}</DialogTitle>
      <DialogContent>
        <Stack spacing={2} sx={{ mt: 0.5 }}>
          <TextField label="Name" value={form.name} onChange={(e) => set("name", e.target.value)} fullWidth autoFocus />
          <Stack direction="row" spacing={2}>
            <TextField select label="Engine" value={form.engine} onChange={(e) => onEngineChange(e.target.value)} sx={{ minWidth: 150 }}>
              <MenuItem value="postgres">PostgreSQL</MenuItem>
              <MenuItem value="mysql">MySQL</MenuItem>
              <MenuItem value="mariadb">MariaDB</MenuItem>
              <MenuItem value="sqlserver">SQL Server</MenuItem>
              <MenuItem value="mongodb">MongoDB</MenuItem>
            </TextField>
            <TextField label="Address (reachable from the jump host)" value={form.address}
              onChange={(e) => set("address", e.target.value)} fullWidth />
            <TextField label="Port" type="number" value={form.port} onChange={(e) => set("port", Number(e.target.value))} sx={{ width: 110 }} />
          </Stack>
          <TextField label="Database name" value={form.databaseName} onChange={(e) => set("databaseName", e.target.value)} fullWidth />
          <TextField select label="Credential (vault password)" value={form.credentialId ?? ""}
            onChange={(e) => set("credentialId", e.target.value || null)} fullWidth
            helperText="The database is authenticated with this vaulted credential; you never see the password.">
            <MenuItem value="">— none —</MenuItem>
            {passwordSecrets.map((s) => <MenuItem key={s.id} value={s.id}>{s.name}{s.username ? ` (${s.username})` : ""}</MenuItem>)}
          </TextField>
          <TextField label="Description" value={form.description} onChange={(e) => set("description", e.target.value)} fullWidth />
          {save.isError && <Alert severity="error">Could not save the database.</Alert>}
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="contained" disabled={save.isPending || !form.name.trim() || !form.address.trim()} onClick={() => save.mutate()}>Save</Button>
      </DialogActions>
    </Dialog>
  );
}
