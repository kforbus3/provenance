import { useState } from "react";
import { Alert, Box, Button, Paper, Stack, TextField, Typography } from "@mui/material";
import { changePassword } from "../api/auth";
import { useAuthStore } from "../store/auth";

// ChangePasswordGate is shown in place of the app when the signed-in account is
// flagged to change its password (e.g. an admin-issued temporary password). The
// backend blocks every non-auth endpoint until the change is made, so this is the
// only screen such a user can act on. On success it reloads the profile, which
// clears the flag and lets the app render normally.
export function ChangePasswordGate() {
  const loadMe = useAuthStore((s) => s.loadMe);
  const logout = useAuthStore((s) => s.logout);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setError(null);
    if (next !== confirm) {
      setError("New passwords do not match.");
      return;
    }
    setBusy(true);
    try {
      await changePassword(current, next);
      await loadMe(); // refreshes the profile; clears mustChangePassword
    } catch (e) {
      const err = e as { response?: { data?: { error?: string } } };
      setError(err.response?.data?.error ?? "Could not change password.");
      setBusy(false);
    }
  };

  return (
    <Box sx={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", p: 2 }}>
      <Paper variant="outlined" sx={{ p: 4, width: "100%", maxWidth: 420 }}>
        <Typography variant="h5" gutterBottom>
          Change your password
        </Typography>
        <Typography color="text.secondary" sx={{ mb: 2 }}>
          Your account must set a new password before continuing.
        </Typography>
        <Stack spacing={2}>
          {error && <Alert severity="error">{error}</Alert>}
          <TextField
            label="Current password" type="password" value={current} autoFocus
            onChange={(e) => setCurrent(e.target.value)}
          />
          <TextField
            label="New password" type="password" value={next}
            onChange={(e) => setNext(e.target.value)}
          />
          <TextField
            label="Confirm new password" type="password" value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") void submit(); }}
          />
          <Button
            variant="contained" onClick={() => void submit()}
            disabled={busy || current === "" || next === ""}
          >
            {busy ? "Changing…" : "Change password"}
          </Button>
          <Button color="inherit" onClick={() => void logout()} disabled={busy}>
            Sign out
          </Button>
        </Stack>
      </Paper>
    </Box>
  );
}
