import { Alert, Grid, MenuItem, Stack, Switch, FormControlLabel, TextField, Typography } from "@mui/material";
import { combinationProblems, invalidPaths, type WritableStateValue } from "./writable-state";

// The writable-state section of the build dialog.
//
// This is what decides where a machine's writes go, and it is the part of an
// image you cannot change afterwards: a machine records the layout it was imaged
// with and refuses a change at boot, because a layout that moved under a running
// system is a system whose data is somewhere it is not looking.
//
// The default — one overlay over the whole root — is what every image built
// before this existed gets, and is what an image with no manifest still gets.
// Everything here is a departure from it, so each control says what it costs.

export function WritableState({ value, onChange }: {
  value: WritableStateValue;
  onChange: (v: WritableStateValue) => void;
}) {
  const set = <K extends keyof WritableStateValue>(k: K, v: WritableStateValue[K]) =>
    onChange({ ...value, [k]: v });

  const problems = combinationProblems(value);

  const pathField = (
    k: keyof WritableStateValue,
    label: string,
    helper: string,
    placeholder: string,
  ) => {
    const bad = invalidPaths(String(value[k]));
    return (
      <Grid item xs={12} sm={6}>
        <TextField
          fullWidth size="small" label={label} value={value[k] as string}
          onChange={(e) => set(k, e.target.value as never)}
          placeholder={placeholder}
          error={bad.length > 0}
          InputProps={{ style: { fontFamily: "monospace", fontSize: 13 } }}
          helperText={bad.length > 0
            ? `Must be absolute paths — the builder skips ${bad.join(", ")}`
            : helper}
        />
      </Grid>
    );
  };

  return (
    <Stack spacing={2}>
      <Typography variant="subtitle2">Writable state</Typography>
      <Typography variant="body2" color="text.secondary">
        Where a machine's writes go. An A/B update replaces the whole root slot, so
        this is what decides which writes survive it. Space-separated absolute paths.
        Under <code>overlay</code> the root is writable and the directories the
        distribution owns are reset on a slot change; under the other two models the
        root is genuinely read-only and only the paths listed here can be written.
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} sm={6}>
          <TextField
            select fullWidth size="small" label="Model" value={value.stateModel}
            onChange={(e) => set("stateModel", e.target.value)}
            helperText={value.stateModel === "overlay"
              ? "One overlay over the whole root. Every write lands on the overlay partition, but /usr, /boot and the package database are reset on a slot change — so packages installed after imaging do not survive an update."
              : value.stateModel === "appliance"
                ? "Read-only root with the smallest writable set the system needs to run."
                : "The root stays read-only and only the paths below are writable."}
          >
            {/* These values go straight to build-image.sh --state-model, which
                accepts overlay|stateful|appliance. "paths" was offered here and
                is not one of them, so choosing it failed the build outright with
                "unknown model 'paths'" -- the non-default option had never once
                produced an image. */}
            <MenuItem value="overlay">overlay — the whole root is writable</MenuItem>
            <MenuItem value="stateful">stateful — read-only root, enumerated writable paths</MenuItem>
            <MenuItem value="appliance">appliance — read-only root, minimal writable state</MenuItem>
          </TextField>
        </Grid>

        <Grid item xs={12} sm={6}>
          <FormControlLabel
            control={
              <Switch
                checked={value.slotPrivateUpper}
                onChange={(e) => set("slotPrivateUpper", e.target.checked)}
              />
            }
            label="Give each slot its own upper layer"
          />
        </Grid>

        {value.slotPrivateUpper && (
          <Grid item xs={12}>
            <Alert severity="info">
              Each slot gets its own <code>upper-A</code> / <code>upper-B</code> instead of
              sharing one. A configuration change made while running A cannot follow you
              into B — so booting the other slot recovers from a bad <em>edit</em>, not only
              a bad image. Each slot keeps its own state until that slot is itself
              updated. The cost is that the two slots stop sharing anything the overlay
              covers. This is recorded in the image and <strong>cannot be changed by an
              update</strong>: a machine refuses a layout change at boot.
            </Alert>
          </Grid>
        )}

        {pathField("persistPaths", "Shared across slots",
          "Survives updates and is the same in both slots — /home, /var/log.",
          "/home /var/log")}
        {pathField("slotPrivatePaths", "Private to each slot",
          "Survives updates but each slot has its own copy.",
          "/etc/machine-state")}
        {pathField("volatilePaths", "Discarded on reboot",
          "tmpfs — nothing written here outlives the boot.",
          "/tmp /var/tmp")}
        {pathField("resetPaths", "Reset when the slot's image is replaced",
          "Cleared when an update rewrites this slot, so stale state cannot cross a release.",
          "/var/cache")}
        {pathField("keepPaths", "Held back from that reset",
          "Exceptions to the line above, kept across the update.",
          "/var/cache/keepme")}
        {pathField("ownPaths", "Also owned by the image",
          "Replaced by the image on update rather than preserved.",
          "/opt/app")}

        {/* build-image.sh refuses these outright, so showing them here is the
            difference between finding out now and finding out when a build that
            has been running for half an hour stops. */}
        {problems.length > 0 && (
          <Grid item xs={12}>
            <Alert severity="error">
              <Typography variant="body2" sx={{ fontWeight: 600, mb: 0.5 }}>
                {problems.length === 1
                  ? "This combination will not build"
                  : `${problems.length} combinations will not build`}
              </Typography>
              {problems.map((p) => (
                <Typography key={p} variant="body2" sx={{ mb: 0.5 }}>{p}</Typography>
              ))}
            </Alert>
          </Grid>
        )}
      </Grid>
    </Stack>
  );
}
