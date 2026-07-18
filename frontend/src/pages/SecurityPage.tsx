import { useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Chip, Divider, IconButton, List,
  ListItem, ListItemText, Stack, TextField, Typography,
} from "@mui/material";
import DeleteIcon from "@mui/icons-material/Delete";
import { QRCodeSVG } from "qrcode.react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  mfaConfirm, mfaDelete, mfaEnroll, mfaList, recoveryStatus, generateRecoveryCodes,
} from "../api/auth";
import { registerPasskey, webauthnSupported } from "../api/webauthn";

// Per-user security settings: enroll and manage TOTP two-factor authentication.
export function SecurityPage() {
  const qc = useQueryClient();
  const { data: methods } = useQuery({ queryKey: ["mfa"], queryFn: mfaList });
  const [secret, setSecret] = useState<string | null>(null);
  const [otpauth, setOtpauth] = useState<string | null>(null);
  const [code, setCode] = useState("");
  const [confirmError, setConfirmError] = useState<string | null>(null);

  const enrollMut = useMutation({
    mutationFn: mfaEnroll,
    onSuccess: (d) => { setSecret(d.secret); setOtpauth(d.otpauthUrl); setConfirmError(null); },
  });
  const confirmMut = useMutation({
    mutationFn: () => mfaConfirm(code),
    onSuccess: () => {
      setSecret(null); setOtpauth(null); setCode("");
      void qc.invalidateQueries({ queryKey: ["mfa"] });
    },
    onError: () => setConfirmError("Invalid code. Try the current code from your app."),
  });
  const deleteMut = useMutation({
    mutationFn: mfaDelete,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["mfa"] }),
  });
  const passkeyMut = useMutation({
    mutationFn: registerPasskey,
    onSuccess: () => qc.invalidateQueries({ queryKey: ["mfa"] }),
  });

  const confirmed = (methods ?? []).filter((m) => m.confirmed);

  return (
    <Box sx={{ maxWidth: 640 }}>
      <Typography variant="h5" gutterBottom>Security</Typography>

      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="h6">Two-factor authentication (TOTP)</Typography>
            <Chip
              size="small"
              label={confirmed.length ? "Enabled" : "Disabled"}
              color={confirmed.length ? "success" : "default"}
            />
          </Stack>
          <Typography color="text.secondary" variant="body2" sx={{ mt: 1 }}>
            Require a one-time code from an authenticator app at sign-in.
          </Typography>

          <List dense sx={{ mt: 1 }}>
            {(methods ?? []).map((m) => (
              <ListItem
                key={m.id}
                secondaryAction={
                  <IconButton edge="end" color="error" onClick={() => deleteMut.mutate(m.id)}>
                    <DeleteIcon />
                  </IconButton>
                }
              >
                <ListItemText
                  primary={`${m.label} (${m.kind})`}
                  secondary={m.confirmed ? "Active" : "Pending confirmation"}
                />
              </ListItem>
            ))}
          </List>

          {!secret && (
            <Button variant="contained" onClick={() => enrollMut.mutate()} disabled={enrollMut.isPending}>
              Set up authenticator
            </Button>
          )}

          {secret && (
            <>
              <Divider sx={{ my: 2 }} />
              <Alert severity="info" sx={{ mb: 2 }}>
                Scan the QR code with your authenticator app (or enter the secret key
                manually), then enter the current 6-digit code to confirm. The secret
                is shown only once.
              </Alert>
              {otpauth && (
                <Box sx={{ display: "flex", justifyContent: "center", mb: 2 }}>
                  {/* Rendered locally — the secret never leaves the browser. */}
                  <Box sx={{ p: 1.5, bgcolor: "#fff", borderRadius: 1, display: "inline-flex" }}>
                    <QRCodeSVG value={otpauth} size={184} />
                  </Box>
                </Box>
              )}
              <TextField
                label="Secret key (manual entry)" value={secret} fullWidth size="small"
                InputProps={{ readOnly: true }} sx={{ mb: 2 }}
                helperText="Use this if you can't scan the QR code"
              />
              {confirmError && <Alert severity="error" sx={{ mb: 1 }}>{confirmError}</Alert>}
              <Stack direction="row" spacing={2}>
                <TextField
                  label="6-digit code" value={code}
                  onChange={(e) => setCode(e.target.value)}
                  inputProps={{ inputMode: "numeric", maxLength: 6 }}
                />
                <Button variant="contained" onClick={() => confirmMut.mutate()} disabled={confirmMut.isPending}>
                  Confirm
                </Button>
              </Stack>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          <Stack direction="row" alignItems="center" justifyContent="space-between">
            <Typography variant="h6">Passkeys (WebAuthn)</Typography>
            <Chip
              size="small"
              label={(methods ?? []).some((m) => m.kind === "webauthn") ? "Registered" : "None"}
              color={(methods ?? []).some((m) => m.kind === "webauthn") ? "success" : "default"}
            />
          </Stack>
          <Typography color="text.secondary" variant="body2" sx={{ mt: 1, mb: 2 }}>
            Use a hardware security key, Touch ID/Windows Hello, or a phone passkey as a
            phishing-resistant second factor.
          </Typography>
          {passkeyMut.isError && (
            <Alert severity="error" sx={{ mb: 2 }}>Passkey registration failed or was cancelled.</Alert>
          )}
          <Button
            variant="contained"
            disabled={!webauthnSupported() || passkeyMut.isPending}
            onClick={() => passkeyMut.mutate()}
          >
            {webauthnSupported() ? "Register a passkey" : "Not supported in this browser"}
          </Button>
        </CardContent>
      </Card>

      <RecoveryCodesCard hasMfa={confirmed.length > 0} />
    </Box>
  );
}

// RecoveryCodesCard manages one-time backup codes usable in place of a second
// factor when the authenticator is lost. Only useful once a second factor exists.
function RecoveryCodesCard({ hasMfa }: { hasMfa: boolean }) {
  const qc = useQueryClient();
  const { data: status } = useQuery({
    queryKey: ["recovery-codes"], queryFn: recoveryStatus, enabled: hasMfa,
  });
  const [codes, setCodes] = useState<string[] | null>(null);
  const gen = useMutation({
    mutationFn: generateRecoveryCodes,
    onSuccess: (c) => { setCodes(c); void qc.invalidateQueries({ queryKey: ["recovery-codes"] }); },
  });

  const download = () => {
    if (!codes) return;
    const blob = new Blob([codes.join("\n") + "\n"], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "fleet-recovery-codes.txt";
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <Card sx={{ mt: 3 }}>
      <CardContent>
        <Stack direction="row" alignItems="center" justifyContent="space-between">
          <Typography variant="h6">Recovery codes</Typography>
          {hasMfa && (
            <Chip size="small"
              label={status ? `${status.remaining} remaining` : "…"}
              color={status && status.remaining > 0 ? "success" : "warning"} />
          )}
        </Stack>
        <Typography color="text.secondary" variant="body2" sx={{ mt: 1, mb: 2 }}>
          One-time codes to sign in if you lose your authenticator or passkey. Each works once.
          Keep them somewhere safe — generating a new set invalidates the old ones.
        </Typography>

        {!hasMfa && (
          <Alert severity="info">Enroll a second factor above first — recovery codes back it up.</Alert>
        )}

        {hasMfa && codes && (
          <Alert severity="success" sx={{ mb: 2 }}>
            <Typography variant="body2" sx={{ fontWeight: 600, mb: 1 }}>
              Save these now — they won't be shown again.
            </Typography>
            <Box sx={{ fontFamily: "monospace", columns: 2, mb: 1 }}>
              {codes.map((c) => <div key={c}>{c}</div>)}
            </Box>
            <Button size="small" onClick={download}>Download .txt</Button>
          </Alert>
        )}

        {hasMfa && (
          <Button variant="contained" disabled={gen.isPending}
            onClick={() => { if (!status?.remaining || window.confirm("Generate a new set? This invalidates your current recovery codes.")) gen.mutate(); }}>
            {status && status.remaining > 0 ? "Regenerate recovery codes" : "Generate recovery codes"}
          </Button>
        )}
      </CardContent>
    </Card>
  );
}
