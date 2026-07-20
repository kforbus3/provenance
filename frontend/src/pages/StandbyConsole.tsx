import { useState } from "react";
import {
  Alert, Box, Button, Card, CardContent, Chip, Stack, TextField, Typography,
} from "@mui/material";
import { useMutation, useQuery } from "@tanstack/react-query";
import { getDRMode, standbyPromote } from "../api/dr";

// StandbyConsole is the full-screen break-glass surface shown when this instance is
// a read-only DR standby (its database is a replica). The normal app is not usable —
// the replica can't service logins — so this is all that renders. It shows live
// replication lag and, with the DR token, promotes the database to primary; the
// instance then restarts into normal operation.
export function StandbyConsole() {
  const [token, setToken] = useState("");
  const { data } = useQuery({ queryKey: ["dr-mode"], queryFn: getDRMode, refetchInterval: 5000 });

  const promote = useMutation({
    mutationFn: () => standbyPromote(token),
  });

  const lag = data?.replayLagSeconds;
  const promotionEnabled = data?.promotionEnabled ?? false;

  return (
    <Box sx={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", p: 2 }}>
      <Card variant="outlined" sx={{ maxWidth: 620, width: "100%" }}>
        <CardContent>
          <Stack direction="row" alignItems="center" spacing={1} sx={{ mb: 1 }}>
            <Typography variant="h5">Disaster Recovery — Standby</Typography>
            <Chip size="small" color="warning" label="read-only" />
          </Stack>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            This instance's database is a <b>replica (in recovery)</b>, so Fleet is running in
            read-only standby mode — normal sign-in and management are unavailable here. Promote it
            to take over as the primary; the instance then restarts into normal operation and you
            manage the fleet from this site's address.
          </Typography>

          <Alert severity="info" sx={{ mb: 2 }}>
            Replication lag:{" "}
            <b>{lag != null ? `${lag.toFixed(1)}s behind primary` : "unknown"}</b>. Promote only once
            the standby is caught up (and the primary is genuinely down or quiesced) — running two
            writable instances at once forks your data.
          </Alert>

          {promote.isSuccess ? (
            <Alert severity="success">
              {promote.data.message} — reload this page in a few seconds.
            </Alert>
          ) : (
            <Stack spacing={2}>
              {promote.isError && (
                <Alert severity="error">
                  {(promote.error as { response?: { data?: { error?: string } } })?.response?.data?.error ?? "Promotion failed"}
                </Alert>
              )}
              {!promotionEnabled && (
                <Alert severity="warning">
                  Console promotion is disabled (no <code>FLEET_DR_STANDBY_TOKEN</code> set). Promote
                  via <code>fleetctl</code> or your database tooling, then restart this instance.
                </Alert>
              )}
              <TextField
                label="DR token" type="password" value={token} fullWidth size="small"
                onChange={(e) => setToken(e.target.value)} disabled={!promotionEnabled}
                helperText="The FLEET_DR_STANDBY_TOKEN configured on this instance"
              />
              <Box>
                <Button
                  variant="contained" color="warning"
                  disabled={!promotionEnabled || !token || promote.isPending}
                  onClick={() => promote.mutate()}
                >
                  {promote.isPending ? "Promoting…" : "Promote this instance to primary"}
                </Button>
              </Box>
            </Stack>
          )}
        </CardContent>
      </Card>
    </Box>
  );
}
