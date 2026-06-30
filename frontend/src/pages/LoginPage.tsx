import { useEffect, useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Stack, TextField, Typography,
} from "@mui/material";
import TerminalIcon from "@mui/icons-material/Terminal";
import { QRCodeSVG } from "qrcode.react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../store/auth";
import { bootstrapStatus, mfaSetupBegin } from "../api/auth";
import { webauthnSupported } from "../api/webauthn";
import { useAppName, useDocumentTitle } from "../api/branding";
import { getOidcStatus, oidcLoginUrl } from "../api/sso";

// Credentials login form. On success the auth store holds the access token and
// principal; we then route to the dashboard. On first run (no users yet) we send
// the operator to the bootstrap wizard instead of showing a sign-in form.
export function LoginPage() {
  const navigate = useNavigate();
  const appName = useAppName();
  useDocumentTitle();
  const login = useAuthStore((s) => s.login);
  const verifyMfa = useAuthStore((s) => s.verifyMfa);
  const verifyPasskey = useAuthStore((s) => s.verifyPasskey);
  const completeMfaSetup = useAuthStore((s) => s.completeMfaSetup);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [challenge, setChallenge] = useState<string | null>(null);
  const [code, setCode] = useState("");
  // Forced MFA enrollment state.
  const [setupToken, setSetupToken] = useState<string | null>(null);
  const [enroll, setEnroll] = useState<{ secret: string; otpauthUrl: string } | null>(null);
  const [sso, setSso] = useState<{ enabled: boolean; buttonText: string } | null>(null);

  useEffect(() => {
    let active = true;
    bootstrapStatus()
      .then((s) => {
        if (active && s.bootstrapAvailable) navigate("/bootstrap", { replace: true });
      })
      .catch(() => {/* backend unreachable — stay on the sign-in form */});
    getOidcStatus().then((s) => active && setSso(s)).catch(() => {/* SSO not configured */});
    return () => {
      active = false;
    };
  }, [navigate]);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (setupToken) {
        await completeMfaSetup(setupToken, code);
        navigate("/", { replace: true });
        return;
      }
      if (challenge) {
        await verifyMfa(challenge, code);
        navigate("/", { replace: true });
        return;
      }
      const res = await login(username, password);
      if (res.mfaRequired && res.challenge) {
        setChallenge(res.challenge);
      } else if (res.mfaEnrollmentRequired && res.setupToken) {
        // MFA is mandatory but not enrolled: fetch a TOTP secret to set up now.
        const token = res.setupToken;
        const data = await mfaSetupBegin(token);
        setSetupToken(token);
        setEnroll(data);
      } else {
        navigate("/", { replace: true });
      }
    } catch (err) {
      setError(extractError(err));
    } finally {
      setSubmitting(false);
    }
  };

  const enrolling = Boolean(setupToken);
  const showCode = Boolean(challenge) || enrolling;

  return (
    <Box
      sx={{
        minHeight: "100vh",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        p: 2,
      }}
    >
      <Card sx={{ width: 380, maxWidth: "100%" }}>
        <CardContent sx={{ p: 4 }}>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 3 }}>
            <TerminalIcon color="primary" />
            <Typography variant="h6" sx={{ fontWeight: 600 }}>
              {appName}
            </Typography>
          </Stack>
          <Typography variant="h5" gutterBottom>
            {enrolling ? "Set up two-factor" : challenge ? "Two-factor verification" : "Sign in"}
          </Typography>
          <Box component="form" onSubmit={onSubmit} sx={{ mt: 2 }}>
            <Stack spacing={2}>
              {error && <Alert severity="error">{error}</Alert>}
              {enrolling && enroll && (
                <Alert severity="info" sx={{ wordBreak: "break-all" }}>
                  Two-factor authentication is required for your account. Scan this
                  QR code with your authenticator app (or enter the secret key
                  manually), then enter the 6-digit code below.
                  <Box sx={{ display: "flex", justifyContent: "center", my: 1.5 }}>
                    <Box sx={{ p: 1.5, bgcolor: "#fff", borderRadius: 1, display: "inline-flex" }}>
                      <QRCodeSVG value={enroll.otpauthUrl} size={172} />
                    </Box>
                  </Box>
                  <Box sx={{ fontFamily: "monospace", fontSize: 14, letterSpacing: 1 }}>
                    {enroll.secret}
                  </Box>
                </Alert>
              )}
              {showCode ? (
                <TextField
                  label="Authenticator code"
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                  autoFocus
                  fullWidth
                  required
                  inputProps={{ inputMode: "numeric", pattern: "[0-9]*", maxLength: 6 }}
                  helperText="Enter the 6-digit code from your authenticator app"
                />
              ) : (
                <>
                  <TextField
                    label="Username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoFocus
                    fullWidth
                    required
                  />
                  <TextField
                    label="Password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    fullWidth
                    required
                  />
                </>
              )}
              <Button
                type="submit"
                variant="contained"
                size="large"
                disabled={submitting}
              >
                {submitting ? "Please wait…" : enrolling ? "Confirm & sign in" : challenge ? "Verify" : "Sign in"}
              </Button>
              {sso?.enabled && !challenge && !enrolling && (
                <>
                  <Typography variant="caption" color="text.secondary" align="center">or</Typography>
                  <Button variant="outlined" size="large" onClick={() => window.location.assign(oidcLoginUrl())}>
                    {sso.buttonText || "Sign in with SSO"}
                  </Button>
                </>
              )}
              {challenge && !enrolling && webauthnSupported() && (
                <Button
                  variant="outlined"
                  onClick={async () => {
                    setError(null);
                    setSubmitting(true);
                    try {
                      await verifyPasskey(challenge);
                      navigate("/", { replace: true });
                    } catch {
                      setError("Passkey verification failed or was cancelled.");
                    } finally {
                      setSubmitting(false);
                    }
                  }}
                >
                  Use a passkey instead
                </Button>
              )}
            </Stack>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}

interface ApiErrorShape {
  response?: { data?: { error?: string } };
}

function extractError(err: unknown): string {
  const e = err as ApiErrorShape;
  return e.response?.data?.error ?? "Sign in failed. Please try again.";
}
