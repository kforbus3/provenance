// The writable-state values and their validation, kept out of the component file
// so fast refresh keeps working there — and so the path rule can be tested.

export interface WritableStateValue {
  stateModel: string;
  slotPrivateUpper: boolean;
  persistPaths: string;
  slotPrivatePaths: string;
  volatilePaths: string;
  resetPaths: string;
  keepPaths: string;
  ownPaths: string;
}

export const WRITABLE_STATE_DEFAULT: WritableStateValue = {
  stateModel: "overlay",
  slotPrivateUpper: false,
  persistPaths: "",
  slotPrivatePaths: "",
  volatilePaths: "",
  resetPaths: "",
  keepPaths: "",
  ownPaths: "",
};

// A path directive only means anything if it is absolute — the builder silently
// skips anything else, so a typo would be a directive that appears to have been
// accepted and is not in the image. Said here instead.
export function invalidPaths(value: string): string[] {
  return value
    .split(/\s+/)
    .filter(Boolean)
    .filter((p) => !p.startsWith("/"));
}

// What each state model resets on a slot change, before anything the operator
// adds. Mirrored from build-image.sh, which is the authority: it refuses these
// combinations at build time whatever this file says. The copy exists so the
// dialog can refuse in the moment rather than after a thirty-minute build, and
// deploy/builder-runner/test_state_model_guards.py fails if the two drift.
//
// The overlay model also resets the package database, whose path depends on the
// distribution. Both families' paths are listed because this dialog does not
// know which one is selected, and the consequence of listing both is only that
// a keep under the *other* family's database is refused here rather than at
// build time — which is the right answer either way.
export const MODEL_RESET_PATHS: Record<string, string[]> = {
  overlay: [
    "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/boot",
    "/var/lib/dpkg", "/var/lib/apt", "/var/cache/apt",
    "/var/lib/rpm", "/var/lib/dnf", "/var/cache/dnf",
  ],
  stateful: [
    "/var/lib/dpkg", "/var/lib/apt", "/var/cache/apt",
    "/var/lib/rpm", "/var/lib/dnf", "/var/cache/dnf",
  ],
  appliance: ["/var"],
};

// Keeps held by a model rather than typed by the operator. Only the LUKS
// enrollment directory, and only when the image is encrypted and something
// resets /etc — build-image.sh adds it for exactly that case.
const IMPLICIT_KEEPS = ["/etc/cryptsetup-keys.d"];

function within(child: string, parent: string): boolean {
  return child.startsWith(parent.endsWith("/") ? parent : parent + "/");
}

/** Option combinations build-image.sh will refuse, explained in the operator's terms.
 *
 * A keep is a carve-out from a reset and only from a reset. Keeping exactly what
 * is reset cancels the reset, so the machine goes on serving its own copy of
 * something the update replaced — an update that reports success and changes
 * nothing. Keeping a path nothing resets carves nothing out, and the boot script
 * implements it by moving live data out of the store and back on every slot
 * change, which can only lose it.
 */
export function combinationProblems(value: WritableStateValue): string[] {
  const resets = [
    ...(MODEL_RESET_PATHS[value.stateModel] ?? []),
    ...value.resetPaths.split(/\s+/).filter(Boolean),
  ];
  const problems: string[] = [];

  for (const keep of value.keepPaths.split(/\s+/).filter(Boolean)) {
    if (!keep.startsWith("/")) continue;         // already reported as invalid
    if (IMPLICIT_KEEPS.includes(keep)) continue;

    if (resets.includes(keep)) {
      problems.push(
        `${keep} is both reset and kept, which cancels the reset. An update would ` +
        `leave this machine's ${keep} shadowing the one it just installed, and the ` +
        `update would report success while the machine kept running the old release. ` +
        `Keep something inside ${keep} instead.`,
      );
    } else if (!resets.some((r) => within(keep, r))) {
      problems.push(
        `${keep} is not inside anything that gets reset, so keeping it does nothing — ` +
        `it already survives a slot change under the ${value.stateModel} model.`,
      );
    }
  }
  return problems;
}
