import { useEffect, useRef, useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Chip, CircularProgress, Divider, Stack, Typography,
} from "@mui/material";
import UploadFileIcon from "@mui/icons-material/UploadFile";

import CloudDownloadIcon from "@mui/icons-material/CloudDownload";

import { getVersion } from "../../api/client";
import {
  applyUpgrade, checkForUpdate, CheckResult, getUpgradeStatus, previewUpgrade, pullUpdate,
  UpgradeManifest, UpgradeStatus,
} from "../../api/upgrade";

// UpdatesCard is the Settings -> Maintenance panel for the in-UI upgrade system:
// upload a signed .fleetup bundle, review its manifest, then apply it in place. It
// tolerates the backend restart mid-upgrade (the updater sidecar holds the status).
export function UpdatesCard() {
  const [current, setCurrent] = useState<string>("");
  const [manifest, setManifest] = useState<UpgradeManifest | null>(null);
  const [status, setStatus] = useState<UpgradeStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>("");
  const [reconnecting, setReconnecting] = useState(false);
  const [check, setCheck] = useState<CheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const polling = useRef<number | null>(null);

  useEffect(() => {
    getVersion().then((v) => setCurrent(v.version)).catch(() => {});
    // Best-effort check on mount so an available update surfaces without a click.
    checkForUpdate().then(setCheck).catch(() => {});
    return () => { if (polling.current) window.clearInterval(polling.current); };
  }, []);

  async function onCheck() {
    setError(""); setChecking(true);
    try {
      setCheck(await checkForUpdate());
    } catch (e: any) {
      setError(e?.response?.data?.error || e?.message || "Could not reach the update channel.");
    } finally {
      setChecking(false);
    }
  }

  async function onPull() {
    if (!check?.release) return;
    setError(""); setBusy(true);
    try {
      await pullUpdate(check.release.version);
      setStatus({ state: "running", targetVersion: check.release.version, step: "downloading…" });
      startPolling();
    } catch (e: any) {
      setError(e?.response?.data?.error || e?.message || "Could not start the update.");
    } finally {
      setBusy(false);
    }
  }

  const active = status && (status.state === "dispatched" || status.state === "running" || status.state === "backing_up");

  function startPolling() {
    if (polling.current) window.clearInterval(polling.current);
    polling.current = window.setInterval(async () => {
      try {
        const s = await getUpgradeStatus();
        setReconnecting(false);
        setStatus(s);
        if (s.state === "success" || s.state === "failed") {
          if (polling.current) window.clearInterval(polling.current);
        }
      } catch {
        // Expected while the backend restarts — keep polling, show "reconnecting".
        setReconnecting(true);
      }
    }, 3000);
  }

  async function onPreview() {
    const file = fileRef.current?.files?.[0];
    if (!file) return;
    setError(""); setManifest(null); setBusy(true);
    try {
      setManifest(await previewUpgrade(file));
    } catch (e: any) {
      setError(e?.response?.data?.error || e?.message || "Could not read that bundle.");
    } finally {
      setBusy(false);
    }
  }

  async function onApply() {
    if (!manifest) return;
    setError(""); setBusy(true);
    try {
      await applyUpgrade(manifest.version);
      setStatus({ state: "running", targetVersion: manifest.version, step: "starting…" });
      startPolling();
    } catch (e: any) {
      setError(e?.response?.data?.error || e?.message || "Could not start the upgrade.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card variant="outlined" sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>Updates</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          Running version <code>{current || "…"}</code>. Upload a signed{" "}
          <code>.fleetup</code> bundle to upgrade in place. The frontend swaps invisibly; the
          backend restarts for a few seconds and this page reconnects automatically. Active
          terminal sessions are dropped, so upgrade during a quiet window.
        </Typography>

        {check?.cluster && check.cluster.length > 1 && (
          <Alert severity={new Set(check.cluster.map((c) => c.version)).size > 1 ? "warning" : "info"} sx={{ mb: 1.5 }}>
            Clustered deployment — {check.cluster.length} instances.{" "}
            {[...new Set(check.cluster.map((c) => c.version))].join(", ")}
            {new Set(check.cluster.map((c) => c.version)).size > 1 ? " (version skew — a rolling upgrade is in progress or incomplete)" : ""}.
            An additive release rolls one instance at a time; a breaking release needs a brief full-cluster maintenance window.
          </Alert>
        )}

        {error && <Alert severity="error" sx={{ mb: 1.5 }} onClose={() => setError("")}>{error}</Alert>}

        {!active && status?.state === "success" && (
          <Alert severity="success" sx={{ mb: 1.5 }}>
            Upgraded to {status.targetVersion}. <Button size="small" onClick={() => window.location.reload()}>Reload</Button>
          </Alert>
        )}
        {!active && status?.state === "failed" && (
          <Alert severity="error" sx={{ mb: 1.5 }}>
            Upgrade failed: {status.error} {status.error?.includes("rolled back") ? "" : "— check the updater logs."}
          </Alert>
        )}

        {active ? (
          <Box>
            <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
              <CircularProgress size={18} />
              <Typography variant="body2">
                {reconnecting ? "Reconnecting to the backend…" : (status?.step || "Working…")}
                {status?.targetVersion ? ` (→ ${status.targetVersion})` : ""}
              </Typography>
            </Stack>
            {status?.log && status.log.length > 0 && (
              <Box component="pre" sx={{ maxHeight: 160, overflow: "auto", bgcolor: "action.hover", p: 1, borderRadius: 1, fontSize: 12, m: 0 }}>
                {status.log.join("\n")}
              </Box>
            )}
          </Box>
        ) : (
          <>
            {check?.channelEnabled && (
              <Box sx={{ mb: 2 }}>
                <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
                  <Button variant="contained" onClick={onCheck} disabled={checking} startIcon={<CloudDownloadIcon />}>
                    Check for updates
                  </Button>
                  {checking && <CircularProgress size={18} />}
                  {check && !check.updateAvailable && !checking && (
                    <Typography variant="body2" color="text.secondary">You're on the latest version.</Typography>
                  )}
                </Stack>
                {check.updateAvailable && check.release && (
                  <Alert severity="info" sx={{ mt: 1.5 }}
                    action={<Button color="inherit" size="small" onClick={onPull} disabled={busy}>Download &amp; install</Button>}>
                    <b>{check.release.version}</b> is available
                    {check.release.migrationCompatibility === "breaking" ? " (breaking migrations)" : ""}.
                    {check.release.notes ? ` ${check.release.notes}` : ""}
                  </Alert>
                )}
                <Divider sx={{ mt: 2 }}>or upload a bundle</Divider>
              </Box>
            )}
            <Stack direction="row" spacing={1} alignItems="center" flexWrap="wrap">
              <Button variant="outlined" component="label" startIcon={<UploadFileIcon />} disabled={busy}>
                Choose bundle
                <input ref={fileRef} type="file" accept=".fleetup" hidden onChange={onPreview} />
              </Button>
              {busy && <CircularProgress size={18} />}
            </Stack>

            {manifest && (
              <Box sx={{ mt: 2 }}>
                <Divider sx={{ mb: 1.5 }} />
                <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                  <Typography variant="subtitle1">{current} → <b>{manifest.version}</b></Typography>
                  <Chip
                    size="small"
                    color={manifest.migrationCompatibility === "breaking" ? "warning" : "default"}
                    label={manifest.migrationCompatibility === "breaking" ? "Breaking migrations" : "Additive migrations"}
                  />
                  {manifest.components?.map((c) => <Chip key={c} size="small" variant="outlined" label={c} />)}
                </Stack>
                {manifest.notes && (
                  <Typography variant="body2" color="text.secondary" sx={{ whiteSpace: "pre-wrap", mb: 1 }}>
                    {manifest.notes}
                  </Typography>
                )}
                {manifest.migrationCompatibility === "breaking" && (
                  <Alert severity={(check?.cluster?.length ?? 0) > 1 ? "error" : "warning"} sx={{ mb: 1 }}>
                    This release has <b>breaking</b> database migrations.
                    {(check?.cluster?.length ?? 0) > 1
                      ? ` Your ${check!.cluster!.length}-instance cluster will be replaced together (a brief full outage), not rolled one at a time — schedule a maintenance window.`
                      : " On a clustered deployment it requires a maintenance window rather than a rolling upgrade."}
                  </Alert>
                )}
                <Button variant="contained" color="primary" onClick={onApply} disabled={busy}>
                  Install {manifest.version}
                </Button>
              </Box>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
