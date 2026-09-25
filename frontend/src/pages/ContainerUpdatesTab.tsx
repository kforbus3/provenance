import { useMemo, useState } from "react";
import {
  Alert, Autocomplete, Box, Button, Chip, Collapse, FormControlLabel, IconButton, Paper, Snackbar, Stack, Switch, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Tooltip, Typography,
} from "@mui/material";
import RefreshIcon from "@mui/icons-material/Refresh";
import RocketLaunchIcon from "@mui/icons-material/RocketLaunch";
import KeyboardArrowDownIcon from "@mui/icons-material/KeyboardArrowDown";
import KeyboardArrowRightIcon from "@mui/icons-material/KeyboardArrowRight";
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  listContainerUpdates, checkContainerUpdates, rebuildChangedNothing,
  type ImageUpdate, type ImageUpdateHost, type RebuildDiff,
} from "../api/containerUpdates";
import { formatDateTime } from "../lib/datetime";
import { useAuthStore } from "../store/auth";
import { StartRolloutDialog } from "./StartRolloutDialog";

// Available container image updates.
//
// This is the half a renovate bot did — ask the registry what exists — without
// the half that opened merge requests nobody read. The answer lands next to the
// hosts it is true of, so deciding and acting are the same screen.

const errMsg = (e: unknown, fallback: string) =>
  (e as { response?: { data?: { error?: string } } })?.response?.data?.error ?? fallback;

// What this row is telling the operator, as one of four states. Kept in one
// place because the states overlap: an image can have a newer tag AND a moved
// digest, and showing both as separate badges reads as two problems.
type Verdict =
  | "error" | "newer" | "moved" | "current" | "unknown"
  | "local" | "gone" | "self" | "unchecked" | "superseded" | "unavailable"
  // A newer tag exists and a rollout can never apply it: a major version of an
  // image that owns its on-disk format. Its own verdict so it is neither counted
  // as available work nor swept into "roll out everything", where the refusal
  // rejects the whole request and blocks the real updates behind it.
  | "migration";

// hostsOf normalises the hosts list.
//
// The server sends `null` rather than `[]` for an image no host runs any more —
// which is the ordinary case right after an upgrade, since the tags this product
// just replaced still have rows until the next check pass prunes them. One
// `.filter` on that blanked the whole page. Guarding at each use site would work
// until somebody adds the eighth one, so there is one accessor and the rest of
// this file goes through it.
function hostsOf(u: ImageUpdate): ImageUpdateHost[] {
  return u.hosts ?? [];
}

// A row whose repository also has a compose-declared row is not actionable: the
// host's compose has moved past the tag this row names, so a rollout of it is
// skipped as superseded and the container is never recreated. Acting on the
// declared row is what moves it.
export function supersededBy(u: ImageUpdate, all: ImageUpdate[]): ImageUpdate | undefined {
  if (u.declared) return undefined;
  return all.find((o) => o.declared && o.repository === u.repository && o.tag !== u.tag);
}

export function verdictOf(u: ImageUpdate, all: ImageUpdate[] = []): Verdict {
  // Nothing runs this any more. Says so rather than "up to date", which is a
  // claim about something you are running — and this is the row an operator
  // sees immediately after an upgrade, for the tags the upgrade just replaced.
  if (hostsOf(u).length === 0) return "gone";
  // Running, but no registry has been asked about it yet — a host whose
  // containers have only just become visible. Saying so beats leaving the row
  // out, which is indistinguishable from the host having nothing on it.
  if (!u.checkedAt) return "unchecked";
  // Part of Provenance itself. Shown, never offered — this application is
  // upgraded by signed bundle, and a rollout of its own containers could not even
  // report what it did: the backend running the rollout is what gets restarted.
  if (hostsOf(u).every((h) => h.protected)) return "self";
  if (u.error) return "error";
  // Built on the host and never in a registry. Not a problem and not a failure —
  // there is simply nothing to compare against, and showing it as either would
  // put this product's own containers permanently in the needs-attention list.
  if (supersededBy(u, all)) return "superseded";

  // The backend's own verdict, when it has one. Everything below is the
  // fallback for rows written before `status` existed — inferring a verdict
  // from prose, which is how twenty-two up-to-date images came to read
  // "cannot compare".
  switch (u.status) {
    case "local": return "local";
    case "migration": return "migration";
    case "update": return "newer";
    case "moved": return "moved";
    case "unorderable": return "unknown";
    case "unavailable": return "unavailable";
    case "current": return "current";
  }

  if (u.note?.startsWith("built locally")) return "local";
  if (u.latestTag) return "newer";
  if (hostsOf(u).some((h) => h.stale)) return "moved";
  if (u.note && !u.latestTag) return "unknown";
  return "current";
}

// What a rebuilt tag changed. "rebuilt" alone said the bytes differ and nothing
// about how: a base-image security fix and a republish that installs the same 71
// packages at the same versions (nginx:alpine, 2026-09-22) read the same.
export function RebuiltChip({ d }: { d?: RebuildDiff }) {
  const generic = "The tag points at different bytes than these hosts are running — usually a rebuild of the same version.";
  if (!d) {
    return <Tooltip title={generic}><Chip label="rebuilt" size="small" color="info" /></Tooltip>;
  }
  if (!d.ready) {
    return (
      <Tooltip title={`${generic} Comparing the two builds: ${d.reason ?? "not scanned yet"}.`}>
        <Chip label="rebuilt — comparing…" size="small" color="info" variant="outlined" />
      </Tooltip>
    );
  }
  const others = d.otherRunning ? ` Compared with the build most of these hosts run; ${d.otherRunning} other older build(s) are also running.` : "";
  if (rebuildChangedNothing(d)) {
    return (
      <Tooltip title={`The new build installs the same packages at the same versions as the one these hosts run, and changes no vulnerability finding. Updating gains nothing today.${others}`}>
        <Chip label="rebuilt — no package changes" size="small" variant="outlined" />
      </Tooltip>
    );
  }
  const lines: string[] = [];
  for (const c of d.changed.slice(0, 12)) lines.push(`${c.name} ${c.from} → ${c.to}`);
  if (d.changed.length > 12) lines.push(`…and ${d.changed.length - 12} more changed`);
  if (d.added.length) lines.push(`added: ${d.added.slice(0, 8).map((p) => p.name).join(", ")}${d.added.length > 8 ? "…" : ""}`);
  if (d.removed.length) lines.push(`removed: ${d.removed.slice(0, 8).map((p) => p.name).join(", ")}${d.removed.length > 8 ? "…" : ""}`);
  lines.push(`vulnerabilities: ${d.before.total} → ${d.after.total} (critical ${d.before.critical} → ${d.after.critical}, high ${d.before.high} → ${d.after.high}); ${d.fixed} fixed, ${d.introduced} new`);
  if (d.dbDiffers) lines.push("the two builds were scanned against different CVE database builds, so part of that difference may be the data");
  const pkgCount = d.changed.length + d.added.length + d.removed.length;
  const label = d.fixed > 0
    ? `rebuilt — fixes ${d.fixed} vulnerabilit${d.fixed === 1 ? "y" : "ies"}`
    : `rebuilt — ${pkgCount} package${pkgCount === 1 ? "" : "s"} changed`;
  return (
    <Tooltip title={<Box component="span" sx={{ whiteSpace: "pre-line" }}>{lines.join("\n") + others}</Box>}>
      <Chip label={label} size="small" color={d.fixed > 0 ? "warning" : "info"} />
    </Tooltip>
  );
}

function VerdictChip({ u, all = [] }: { u: ImageUpdate; all?: ImageUpdate[] }) {
  const superseded = supersededBy(u, all);
  switch (verdictOf(u, all)) {
    case "superseded":
      return (
        <Tooltip title={`These hosts still run ${u.tag}, but their compose file names ${superseded?.tag}. Updating this row would be skipped — the compose has already moved past it. Update the ${superseded?.tag} row instead; that rewrites the file and recreates the container.`}>
          <Chip label={`superseded by ${superseded?.tag}`} size="small" variant="outlined" />
        </Tooltip>
      );
    case "error":
      return (
        <Tooltip title={u.error ?? ""}>
          <Chip label="could not check" size="small" color="default" variant="outlined" />
        </Tooltip>
      );
    case "newer":
      return <Chip label={`${u.latestTag} available`} size="small" color="warning" />;
    case "migration":
      return (
        <Tooltip title={u.note ?? ""}>
          <Chip label={`${u.latestTag} — migration, not an update`} size="small" color="error" variant="outlined" />
        </Tooltip>
      );
    case "moved":
      return <RebuiltChip d={u.rebuild} />;
    case "unknown":
      return (
        <Tooltip title={u.note ?? ""}>
          <Chip label="cannot compare" size="small" variant="outlined" />
        </Tooltip>
      );
    case "unavailable":
      return (
        <Tooltip title={u.note ?? "The registry would not list this repository's tags — often its own rate limit. The last known listing is used when there is one, and the next check retries."}>
          <Chip label="registry unavailable" size="small" color="warning" variant="outlined" />
        </Tooltip>
      );
    case "unchecked":
      return (
        <Tooltip title="Running here, but no registry has been asked about it yet. The next check picks it up — or press “Check registries now”.">
          <Chip label="not checked yet" size="small" variant="outlined" />
        </Tooltip>
      );
    case "self":
      return (
        <Tooltip title="Part of Provenance itself. Upgraded by signed bundle from Settings → Updates, which verifies the signature, backs up the database, applies migrations and keeps a rollback.">
          <Chip label="upgraded by bundle" size="small" variant="outlined" />
        </Tooltip>
      );
    case "gone":
      return (
        <Tooltip title="No host reports running this image any more — it is left over from a previous version and will be dropped at the next check.">
          <Chip label="no longer running" size="small" variant="outlined" />
        </Tooltip>
      );
    case "local":
      return (
        <Tooltip title="Built on the host rather than pulled from a registry, so there is no published version to compare against.">
          <Chip label="built locally" size="small" variant="outlined" />
        </Tooltip>
      );
    default:
      return <Chip label="up to date" size="small" color="success" variant="outlined" />;
  }
}

function UpdateRow({ u, all, canRun, onRollOut }: {
  u: ImageUpdate; all: ImageUpdate[]; canRun: boolean; onRollOut: (u: ImageUpdate) => void;
}) {
  const [open, setOpen] = useState(false);
  const hosts = hostsOf(u);
  const stale = hosts.filter((h) => h.stale).length;
  const verdict = verdictOf(u, all);
  // Only something actionable can be rolled out. Offering the button on a row
  // that says "up to date" would invite a rollout that deploys the same bytes
  // to every host and reports success for a change nobody made.
  const canRollOut = canRun && (verdict === "newer" || verdict === "moved") &&
    hosts.length > 0 && !hosts.some((h) => h.protected);
  return (
    <>
      <TableRow hover>
        <TableCell sx={{ width: 40 }}>
          <IconButton size="small" onClick={() => setOpen((o) => !o)}>
            {open ? <KeyboardArrowDownIcon fontSize="small" /> : <KeyboardArrowRightIcon fontSize="small" />}
          </IconButton>
        </TableCell>
        <TableCell sx={{ fontFamily: "monospace", fontSize: 12 }}>
          {u.repository}:{u.tag}
        </TableCell>
        <TableCell><VerdictChip u={u} all={all} /></TableCell>
        <TableCell>
          {hosts.length}
          {stale > 0 && (
            <Typography component="span" variant="caption" color="text.secondary">
              {" "}({stale} behind)
            </Typography>
          )}
        </TableCell>
        <TableCell>{u.checkedAt ? formatDateTime(u.checkedAt) : "—"}</TableCell>
        <TableCell align="right">
          {canRollOut && (
            <Tooltip title={verdict === "moved"
              ? "Pull the rebuilt image onto these hosts, a few at a time"
              : `Move these hosts to ${u.latestTag}, a few at a time`}>
              <Button size="small" startIcon={<RocketLaunchIcon fontSize="small" />}
                      onClick={() => onRollOut(u)}>Roll out</Button>
            </Tooltip>
          )}
        </TableCell>
      </TableRow>
      <TableRow>
        <TableCell sx={{ py: 0, borderBottom: open ? undefined : "none" }} colSpan={6}>
          <Collapse in={open} unmountOnExit>
            <Box sx={{ py: 1.5, pl: 5 }}>
              {(u.note || u.error) && (
                <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                  {u.error || u.note}
                </Typography>
              )}
              {u.digest && (
                <Typography variant="caption" color="text.secondary"
                            sx={{ fontFamily: "monospace", display: "block", mb: 1 }}>
                  registry: {u.digest.slice(0, 19)}…
                </Typography>
              )}
              {hosts.length === 0 && (
                <Typography variant="body2" color="text.secondary">
                  No host currently reports running this image.
                </Typography>
              )}
              {hosts.map((h) => (
                <Stack key={`${h.hostId}-${h.container}`} direction="row" spacing={1}
                       alignItems="center" sx={{ mb: 0.5 }}>
                  <Typography variant="body2" sx={{ minWidth: 160 }}>{h.hostname}</Typography>
                  {h.container && (
                    <Typography variant="caption" color="text.secondary"
                                sx={{ fontFamily: "monospace" }}>{h.container}</Typography>
                  )}
                  {h.protected
                    ? <Chip label="part of Provenance — upgraded by bundle" size="small" variant="outlined" />
                    : h.stale
                    ? <Chip label="running older bytes" size="small" color="warning" variant="outlined" />
                    : h.digest
                      ? <Chip label="matches registry" size="small" variant="outlined" />
                      : <Chip label="digest unknown" size="small" variant="outlined" />}
                </Stack>
              ))}
            </Box>
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  );
}

export function ContainerUpdatesTab() {
  const qc = useQueryClient();
  const canScan = useAuthStore((s) => s.has("Host.Scan"));
  const canRun = useAuthStore((s) => s.has("Command.Run"));
  const [filter, setFilter] = useState("");
  // Default: only the images something is actually available for.
  //
  // This screen listed every image the fleet runs -- 52 rows on the deployment
  // this was reported from, of which six were upgradable. The other 46 said
  // "built locally", "upgraded by bundle" or "up to date", which are answers to a
  // question nobody opened this tab to ask. The full list is still worth having:
  // it is how you tell "nothing to upgrade" from "never checked". So it is one
  // click away rather than the default.
  const [showAll, setShowAll] = useState(false);
  // Host is its own control, not part of the text search.
  //
  // One box matching both meant typing a host's name found images whose NAME
  // contained it somewhere else entirely — "docker" turned up a container on
  // control01, which is not what anyone types a hostname to find. An Autocomplete
  // because the two asks are the same control: pick from what is there, and
  // type to narrow it when there is a lot of it.
  const [hostFilter, setHostFilter] = useState<string | null>(null);
  const [snack, setSnack] = useState("");
  const [rollingOut, setRollingOut] = useState<ImageUpdate | null>(null);
  // "Everything with something available", as one rollout rather than one per
  // image: ten separate rollouts each pace themselves, so a canary of one would
  // mean ten hosts taking an unproven update simultaneously.
  const [rollingOutAll, setRollingOutAll] = useState<ImageUpdate[] | null>(null);

  const { data: updates = [], isLoading } = useQuery({
    queryKey: ["container-updates"],
    queryFn: listContainerUpdates,
    placeholderData: keepPreviousData,
  });

  const check = useMutation({
    // Wrapped, so the mutation takes no variable: react-query would otherwise
    // infer the force parameter as a required argument to mutate().
    mutationFn: () => checkContainerUpdates(),
    onSuccess: (r) => setSnack(r.note || "Asking the registries…"),
    onError: (e) => setSnack(errMsg(e, "Could not start a check.")),
  });

  // Every host that reports running something, for the picker.
  const hostOptions = useMemo(() => {
    const names = new Set<string>();
    for (const u of updates) for (const h of hostsOf(u)) if (h.hostname) names.add(h.hostname);
    return [...names].sort((a, b) => a.localeCompare(b));
  }, [updates]);

  const shown = useMemo(() => {
    const q = filter.trim().toLowerCase();
    // The text box searches IMAGES only now; the host picker is exact.
    let rows = q
      ? updates.filter((u) => `${u.repository}:${u.tag}`.toLowerCase().includes(q))
      : updates;
    if (hostFilter) {
      rows = rows.filter((u) => hostsOf(u).some((h) => h.hostname === hostFilter));
    }
    // Actionable first. An operator opening this screen wants the images that
    // need a decision, not an alphabetical list with three of them buried in it.
    // Superseded sits below the actionable rows and above the quiet ones: it is
    // not a decision, but it is the row an operator will look for after
    // wondering why a rollout of the tag above it changed nothing.
    const rank: Record<Verdict, number> = {
      // A migration sits directly under the actionable rows: it is not work anyone
      // can do from here, but it is a decision someone has to make elsewhere, and
      // burying a database that needs migrating among "up to date" rows is how it
      // gets forgotten until the version it is on stops getting security fixes.
      newer: 0, moved: 1, migration: 2, superseded: 3, unavailable: 4, unknown: 5,
      error: 6, unchecked: 7, current: 8, local: 9, self: 10, gone: 11,
    };
    if (!showAll) {
      // Something is available: a newer version, a rebuilt tag, or a major bump
      // that needs a migration. A migration stays in: it IS a new version that
      // exists, and it is the row most worth not forgetting.
      //
      // Rows we could not check stay in too, deliberately. Hiding them would make
      // an empty list mean "nothing to upgrade" when it might mean "we do not
      // know", and the reassuring reading is the dangerous one.
      const keep = new Set<Verdict>(["newer", "moved", "migration", "error", "unchecked"]);
      rows = rows.filter((u) => keep.has(verdictOf(u, updates)));
    }
    return [...rows].sort((a, b) =>
      rank[verdictOf(a, updates)] - rank[verdictOf(b, updates)] ||
      a.repository.localeCompare(b.repository));
  }, [updates, filter, hostFilter, showAll]);

  // Counted separately, because they are not the same news.
  //
  // One line saying "8 images have something newer available" over a list where
  // seven rows read "rebuilt" and one reads "1.27 available" invites exactly the
  // question it got: why does only one show an update? Both are actionable and
  // only one is a new VERSION — which is the distinction the rest of this screen
  // is built around, so the summary should not be the one place that flattens it.
  const canAct = (u: ImageUpdate) =>
    hostsOf(u).length > 0 && !hostsOf(u).some((h) => h.protected);
  const newerUpdates = updates.filter((u) => verdictOf(u, updates) === "newer" && canAct(u));
  const rebuiltUpdates = updates.filter((u) => verdictOf(u, updates) === "moved" && canAct(u));
  const actionableUpdates = [...newerUpdates, ...rebuiltUpdates];
  const actionable = actionableUpdates.length;

  return (
    <Box>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
        What the registries say is available for the images your hosts are running.
        Checked twice a day; a newer version tag and a rebuilt tag are reported
        separately, because a rebuild keeps the same version number.
        The images themselves are discovered by the monitor sweep as it reaches each
        host, so a newly added host appears here once it has been swept.
      </Typography>

      <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 2 }}>
        <Autocomplete
          size="small"
          options={hostOptions}
          value={hostFilter}
          onChange={(_, v) => setHostFilter(v)}
          sx={{ minWidth: 240 }}
          renderInput={(params) => (
            <TextField {...params} label="Host"
                       placeholder={hostOptions.length ? "All hosts" : "No hosts reporting"} />
          )}
          noOptionsText="No host matches"
        />
        <TextField size="small" placeholder="Filter by image"
                   value={filter} onChange={(e) => setFilter(e.target.value)}
                   sx={{ maxWidth: 280, flex: 1 }} />
        {/* The full list answers a different question -- "what are we running, and
            has it been checked" -- which is worth being able to ask, and is not what
            this tab is opened for. */}
        <FormControlLabel
          sx={{ whiteSpace: "nowrap", mr: 0 }}
          control={<Switch size="small" checked={showAll}
                           onChange={(e) => setShowAll(e.target.checked)} />}
          label={<Typography variant="body2">
            {showAll ? `All ${updates.length} images` : "Only what can be upgraded"}
          </Typography>}
        />
        {canScan && (
          <Tooltip title="Re-asks the registries about the images already discovered. It does not go out to your hosts — that is the monitor sweep's job.">
            <span>
              <Button startIcon={<RefreshIcon />} disabled={check.isPending}
                      onClick={() => check.mutate()}>Check registries now</Button>
            </span>
          </Tooltip>
        )}
        <Button size="small" onClick={() => qc.invalidateQueries({ queryKey: ["container-updates"] })}>
          Refresh
        </Button>
      </Stack>

      {actionable > 0 && (
        <Alert
          severity="warning"
          sx={{ mb: 2 }}
          action={canRun ? (
            <Button color="inherit" size="small"
                    onClick={() => setRollingOutAll(actionableUpdates)}>
              Update all
            </Button>
          ) : undefined}
        >
          {[
            newerUpdates.length > 0 &&
              `${newerUpdates.length} image${newerUpdates.length > 1 ? "s have" : " has"} a newer version`,
            rebuiltUpdates.length > 0 &&
              `${rebuiltUpdates.length} ${rebuiltUpdates.length > 1 ? "have" : "has"} been rebuilt at the same version`,
          ].filter(Boolean).join(", and ")}.
          {rebuiltUpdates.length > 0 && (
            <Typography variant="caption" color="inherit" sx={{ display: "block", mt: 0.5 }}>
              A rebuild is the same version republished — usually a patched base
              image. It shows as “rebuilt” rather than a version number, which is
              why the list may look shorter than the count.
            </Typography>
          )}
        </Alert>
      )}

      {isLoading && <Typography variant="body2">Loading…</Typography>}
      {!isLoading && updates.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          Nothing here yet. Images are discovered by the monitor sweep as it reaches
          each host, and the registries are asked shortly afterwards — so a fleet that
          has just upgraded fills in over the following few sweeps rather than all at
          once. “Check registries now” re-asks about images already discovered; it does
          not reach out to your hosts, so it will not make an unswept host appear.
        </Typography>
      )}

      {!isLoading && updates.length > 0 && shown.length === 0 && (
        <Typography variant="body2" color="text.secondary">
          Nothing matches{hostFilter ? ` on ${hostFilter}` : ""}
          {filter.trim() ? ` for “${filter.trim()}”` : ""}.
          {" "}({updates.length} image{updates.length === 1 ? "" : "s"} in total.)
        </Typography>
      )}

      {shown.length > 0 && (
        <TableContainer component={Paper} variant="outlined" sx={{ overflowX: "auto" }}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell />
                <TableCell>Image</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Hosts</TableCell>
                <TableCell>Checked</TableCell>
                <TableCell />
              </TableRow>
            </TableHead>
            <TableBody>
              {shown.map((u) => (
                <UpdateRow key={`${u.repository}:${u.tag}`} u={u} all={updates} canRun={canRun}
                           onRollOut={setRollingOut} />
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      <StartRolloutDialog update={rollingOut} updates={rollingOutAll}
                          onClose={() => { setRollingOut(null); setRollingOutAll(null); }}
                          onStarted={(m) => {
                            setSnack(m);
                            qc.invalidateQueries({ queryKey: ["rollouts"] });
                          }} />

      <Snackbar open={!!snack} autoHideDuration={6000} onClose={() => setSnack("")}
                message={snack} />
    </Box>
  );
}
