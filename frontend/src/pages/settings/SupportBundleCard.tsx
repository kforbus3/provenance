import { useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, CircularProgress, Link, Stack, Typography,
} from "@mui/material";
import DownloadIcon from "@mui/icons-material/Download";
import { api } from "../../api/client";

// A support bundle about Provenance itself.
//
// The host bundle answers "what is wrong with that machine". This answers "what
// is wrong with this application" — so reporting a problem does not require
// knowing which container to exec into, which log to tail, or which table to
// query. One button, one file, readable offline.

export function SupportBundleCard() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function download() {
    setError(""); setBusy(true);
    try {
      // Fetched as a blob rather than navigated to: the request carries the
      // session's auth header, which a plain link would not.
      const res = await api.get("/api/v1/system/support-bundle", { responseType: "blob" });
      const name =
        /filename="([^"]+)"/.exec(res.headers["content-disposition"] ?? "")?.[1] ??
        "provenance-support.tar.gz";
      const url = URL.createObjectURL(res.data as Blob);
      const a = document.createElement("a");
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e?.response?.data?.error || e?.message || "Could not build the bundle.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card variant="outlined" sx={{ mb: 2 }}>
      <CardContent>
        <Typography variant="h6" gutterBottom>Support bundle</Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mb: 1.5 }}>
          A single file describing this instance — versions and cluster members,
          applied migrations, scheduled job results, dependency health, a fleet
          summary, and recent logs from every Provenance container. Attach it to a
          problem report so somebody can work offline from what actually happened.
        </Typography>

        {/* What is in it, and what is not, stated before the button rather than
            after the download — the moment to decide is before it leaves. */}
        <Alert severity="info" sx={{ mb: 1.5 }}>
          <Typography variant="body2" component="div">
            Before you send it:
            <Box component="ul" sx={{ pl: 2.5, my: 0.5 }}>
              <li>
                <b>Hostnames are included.</b> IP addresses are replaced with
                placeholders from the ranges reserved for documentation.
              </li>
              <li>
                The same address maps to the same placeholder throughout, so
                “these two lines are the same machine” is still readable — but the
                mapping is unique to each bundle, so two bundles cannot be lined
                up against each other.
              </li>
              <li>
                Passwords, tokens, keys and connection-string credentials are
                removed. Configuration is reported from a fixed list of non-secret
                fields rather than from the environment.
              </li>
              <li>
                Nothing is stored on the server — the file is built as it
                downloads.
              </li>
            </Box>
            The bundle’s <code>manifest.json</code> repeats all of this, and records
            how many addresses were replaced.
          </Typography>
        </Alert>

        {error && <Alert severity="error" sx={{ mb: 1.5 }} onClose={() => setError("")}>{error}</Alert>}

        <Stack direction="row" spacing={1} alignItems="center">
          <Button variant="contained" startIcon={<DownloadIcon />}
                  onClick={download} disabled={busy}>
            Download support bundle
          </Button>
          {busy && <CircularProgress size={18} />}
          {busy && (
            <Typography variant="body2" color="text.secondary">
              Collecting container logs — this takes a moment.
            </Typography>
          )}
        </Stack>

        <Typography variant="caption" color="text.secondary" sx={{ display: "block", mt: 1.5 }}>
          If the interface itself is unavailable, the same bundle can be produced
          from the host with{" "}
          <Link component="span" sx={{ fontFamily: "monospace" }}>fleetctl support-bundle</Link>.
        </Typography>
      </CardContent>
    </Card>
  );
}
