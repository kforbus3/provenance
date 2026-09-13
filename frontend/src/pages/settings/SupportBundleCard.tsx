import { useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Checkbox, CircularProgress,
  FormControlLabel, Link, Stack, Typography,
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
  // Off by default. A bundle usually goes to somebody who already knows the
  // estate, and the real names make it far easier to read; masking is for when
  // it is going further afield.
  const [anonymise, setAnonymise] = useState(false);

  async function download() {
    setError(""); setBusy(true);
    try {
      // Fetched as a blob rather than navigated to: the request carries the
      // session's auth header, which a plain link would not.
      const res = await api.get("/api/v1/system/support-bundle", {
        responseType: "blob",
        params: anonymise ? { anonymise: 1 } : undefined,
      });
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
        <FormControlLabel
          sx={{ mb: 1 }}
          control={<Checkbox checked={anonymise}
                             onChange={(e) => setAnonymise(e.target.checked)} />}
          label="Mask hostnames and IP addresses"
        />

        {/* What is in it, stated before the button rather than after the
            download — the moment to decide is before it leaves. */}
        <Alert severity={anonymise ? "success" : "warning"} sx={{ mb: 1.5 }}>
          <Typography variant="body2" component="div">
            {anonymise ? (
              <>
                Hostnames will be masked and IP addresses replaced with placeholders
                from the ranges reserved for documentation.
                <Box component="ul" sx={{ pl: 2.5, my: 0.5 }}>
                  <li>
                    The same name and the same address map to the same placeholder
                    throughout, so “these two lines are the same machine” is still
                    readable. The mapping is unique to each bundle, so two bundles
                    cannot be lined up against each other.
                  </li>
                  <li>
                    A hostname that is also an ordinary word — <code>docker</code>,{" "}
                    <code>repo</code> — is replaced <em>wherever</em> it appears,
                    including where it did not mean the host. The manifest lists
                    which ones those were.
                  </li>
                  <li>Loopback and unspecified addresses are left as they are.</li>
                </Box>
              </>
            ) : (
              <>
                <b>Hostnames and IP addresses will be included as they are.</b> This
                bundle will describe your real network — fine for somebody who
                already knows it, worth reconsidering if it is going further afield.
                Tick the box above to mask them.
              </>
            )}
            Passwords, tokens, keys and connection-string credentials are removed
            either way, and configuration is reported from a fixed list of
            non-secret fields rather than from the environment. Nothing is stored on
            the server — the file is built as it downloads.
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
          <Link component="span" sx={{ fontFamily: "monospace" }}>
            provctl support-bundle
          </Link>{" "}
          (add <code>--anonymise</code> for the same masking).
        </Typography>
      </CardContent>
    </Card>
  );
}
