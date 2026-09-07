// Which distributions the builder offers, and what a "suite" means for each.
//
// Kept out of the dialog so it can be tested (and so fast refresh keeps working
// there). The builder branches on the package family for the bootstrapper, the
// initramfs generator and the bootloader; the UI needs it for one thing only —
// whether a release is a codename or a major version.

export function distroFamily(distro: string): "deb" | "rpm" {
  return distro === "almalinux" || distro === "rocky" ? "rpm" : "deb";
}

// The suite that goes with a distribution when you pick it. Switching from
// Debian to Rocky and leaving "trixie" in the box is a build the builder refuses
// — and the reason arrives minutes later, from a container. The box changes with
// the choice instead of waiting to be corrected.
export const DEFAULT_SUITE: Record<string, string> = {
  debian: "trixie",
  ubuntu: "noble",
  almalinux: "9",
  rocky: "9",
};

// RPM releases are a closed set named by major version — this family has no
// codenames. Offering them as a list makes the wrong answer unreachable rather
// than merely discouraged. Debian and Ubuntu codenames stay free text, because
// that set is open and changes faster than a dropdown would.
export const RPM_SUITES = ["10", "9", "8"];
