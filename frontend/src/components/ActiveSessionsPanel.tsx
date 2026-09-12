import { useEffect, useState } from "react";
import {
  Alert, Box, Button, Chip, Dialog, DialogActions, DialogContent, DialogContentText,
  DialogTitle, InputAdornment, Paper, Snackbar, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import LogoutIcon from "@mui/icons-material/Logout";
import SearchIcon from "@mui/icons-material/Search";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDateTime } from "../lib/datetime";
import { listActiveSessions, terminateSession, type ActiveSession } from "../api/admin";
import { useAuthStore } from "../store/auth";

// Who is signed in right now, and the means to cut one of them off.
//
// This is the oversight view, not a self-service one: it lists every user's
// sessions, and it is gated on Session.Terminate — the same permission the
// "terminate all sessions" action on a user already carries.
//
// Terminating here ends ONE sign-in. The per-user action ends all of them, which
// is the right answer for a departing employee and too blunt for a laptop left
// logged in at a client site.

const rel = (iso: string) => {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (!Number.isFinite(mins)) return "";
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const h = Math.floor(mins / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

// A user agent is unreadable at full length and is the only clue to which device
// a session belongs, so it is shortened rather than dropped.
const device = (ua?: string) => {
  if (!ua) return "unknown";
  const m = ua.match(/(Firefox|Edg|Chrome|Safari)\/[\d.]+/);
  const os = /Windows/.test(ua) ? "Windows"
    : /Mac OS X|Macintosh/.test(ua) ? "macOS"
    : /Android/.test(ua) ? "Android"
    : /iPhone|iPad/.test(ua) ? "iOS"
    : /Linux/.test(ua) ? "Linux" : "";
  const browser = m ? m[0].split("/")[0].replace("Edg", "Edge") : "";
  return [browser, os].filter(Boolean).join(" on ") || ua.slice(0, 40);
};

export function ActiveSessionsPanel() {
  const qc = useQueryClient();
  // The store's own helper, not permissions.includes: it also honours
  // Admin.All and super-admin status, so a super administrator would otherwise
  // be shown an empty panel on a screen built for exactly that audience.
  const canTerminate = useAuthStore((s) => s.has("Session.Terminate"));
  const [confirm, setConfirm] = useState<ActiveSession | null>(null);
  const [search, setSearch] = useState("");
  // Debounced so typing does not issue a request per keystroke.
  const [query, setQuery] = useState("");
  useEffect(() => {
    const t = setTimeout(() => setQuery(search), 300);
    return () => clearTimeout(t);
  }, [search]);
  const [snack, setSnack] = useState("");

  const { data: sessions = [], isLoading, error } = useQuery({
    queryKey: ["active-sessions", query],
    queryFn: () => listActiveSessions(query),
    enabled: canTerminate,
    // Someone signing in or out is the thing this screen is for, so it should
    // not need a manual reload to be true.
    refetchInterval: 30_000,
  });

  const kill = useMutation({
    mutationFn: terminateSession,
    onSuccess: () => {
      setConfirm(null);
      setSnack("Session terminated");
      void qc.invalidateQueries({ queryKey: ["active-sessions"] });
    },
    onError: () => setSnack("Could not terminate that session"),
  });

  if (!canTerminate) return null;

  return (
    <Paper sx={{ p: 2, mt: 3 }}>
      <Typography variant="h6" gutterBottom>Active sign-ins</Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        Everyone currently signed in to the web interface. Ending a sign-in closes
        any terminal open on it and revokes its certificates — it does not only
        mark it expired.
      </Typography>

      <TextField
        size="small" fullWidth value={search} sx={{ mb: 2 }}
        onChange={(e) => setSearch(e.target.value)}
        placeholder="Filter by user, display name or address"
        InputProps={{
          startAdornment: (
            <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment>
          ),
        }}
      />

      {error && <Alert severity="error" sx={{ mb: 2 }}>Could not load sessions.</Alert>}
      {isLoading && <Typography variant="body2">Loading…</Typography>}

      {!isLoading && sessions.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          {query ? `No sign-ins match “${query}”.` : "Nobody is signed in."}
        </Typography>
      )}

      {sessions.length > 0 && (
        <TableContainer sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>User</TableCell>
                <TableCell>Device</TableCell>
                <TableCell>IP</TableCell>
                <TableCell>Last seen</TableCell>
                <TableCell>Signed in</TableCell>
                <TableCell align="right">Action</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {sessions.map((s) => (
                  <TableRow key={s.id} hover>
                    <TableCell>
                      {s.displayName || s.username}
                      {s.displayName && (
                        <Typography variant="caption" color="text.secondary" sx={{ ml: 0.5 }}>
                          ({s.username})
                        </Typography>
                      )}
                      {!s.mfaPassed && (
                        <Tooltip title="This session did not complete multi-factor authentication">
                          <Chip label="no MFA" size="small" color="warning"
                                variant="outlined" sx={{ ml: 1 }} />
                        </Tooltip>
                      )}
                    </TableCell>
                    <TableCell>{device(s.userAgent)}</TableCell>
                    <TableCell sx={{ fontFamily: "monospace", fontSize: 13 }}>
                      {s.ip || "—"}
                    </TableCell>
                    <TableCell>
                      <Tooltip title={formatDateTime(s.lastSeenAt)}>
                        <span>{rel(s.lastSeenAt)}</span>
                      </Tooltip>
                    </TableCell>
                    <TableCell>
                      <Tooltip title={formatDateTime(s.createdAt)}>
                        <span>{rel(s.createdAt)}</span>
                      </Tooltip>
                    </TableCell>
                    <TableCell align="right">
                      <Button
                        size="small" color="error" startIcon={<LogoutIcon />}
                        onClick={() => setConfirm(s)}
                      >
                        Terminate
                      </Button>
                    </TableCell>
                  </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* Terminating cannot be undone and the person on the other end loses
          whatever they were doing, so it is confirmed — and says whose it is,
          because a table row is easy to click one line off. */}
      <Dialog open={confirm !== null} onClose={() => setConfirm(null)}>
        <DialogTitle>Terminate this sign-in?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {confirm && (
              <>
                <strong>{confirm.displayName || confirm.username}</strong> will be
                signed out of {device(confirm.userAgent)}
                {confirm.ip ? ` at ${confirm.ip}` : ""}. Any terminal open on this
                sign-in closes immediately.
                <Box component="span" sx={{ display: "block", mt: 1 }}>
                  If this is the session you are using now, you will have to sign in again.
                </Box>
              </>
            )}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirm(null)}>Cancel</Button>
          <Button
            color="error" variant="contained" disabled={kill.isPending}
            onClick={() => confirm && kill.mutate(confirm.id)}
          >
            Terminate
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={snack !== ""} autoHideDuration={4000}
        onClose={() => setSnack("")} message={snack}
      />
    </Paper>
  );
}
