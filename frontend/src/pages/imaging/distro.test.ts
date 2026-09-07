import { describe, expect, it } from "vitest";
import { distroFamily, DEFAULT_SUITE, RPM_SUITES } from "./distro";

// The builder branches on the package family for the bootstrapper, the initramfs
// generator and the bootloader. The UI needs it for one thing: what a "suite" is.
describe("distroFamily", () => {
  it("puts the RPM distributions in the rpm family", () => {
    expect(distroFamily("almalinux")).toBe("rpm");
    expect(distroFamily("rocky")).toBe("rpm");
  });

  it("leaves the Debian ones alone", () => {
    expect(distroFamily("debian")).toBe("deb");
    expect(distroFamily("ubuntu")).toBe("deb");
  });

  // An unknown name must not be treated as RPM: the deb path is what the builder
  // itself defaults to, so guessing rpm here would disagree with it.
  it("defaults an unknown distribution to deb", () => {
    expect(distroFamily("")).toBe("deb");
    expect(distroFamily("suse")).toBe("deb");
  });
});

describe("DEFAULT_SUITE", () => {
  // Switching from Debian to Rocky and leaving "trixie" in the box is a build the
  // builder refuses — and the reason arrives minutes later, from a container. The
  // suite follows the distribution instead.
  it("gives every offered distribution a suite of its own family", () => {
    expect(DEFAULT_SUITE.debian).toBe("trixie");
    expect(DEFAULT_SUITE.ubuntu).toBe("noble");
    expect(DEFAULT_SUITE.almalinux).toBe("9");
    expect(DEFAULT_SUITE.rocky).toBe("9");
  });

  it("gives the RPM distributions a major version, not a codename", () => {
    for (const d of ["almalinux", "rocky"]) {
      expect(DEFAULT_SUITE[d], d).toMatch(/^\d+$/);
      expect(RPM_SUITES).toContain(DEFAULT_SUITE[d]);
    }
  });

  it("gives the deb distributions a codename, not a number", () => {
    for (const d of ["debian", "ubuntu"]) {
      expect(DEFAULT_SUITE[d], d).not.toMatch(/^\d+$/);
    }
  });

  // Every entry must be one the builder accepts for that family, or the default
  // is a build that fails on the first thing it validates.
  it("has an entry for every distribution the dropdown offers", () => {
    for (const d of ["debian", "ubuntu", "almalinux", "rocky"]) {
      expect(DEFAULT_SUITE[d], d).toBeTruthy();
    }
  });
});

describe("RPM_SUITES", () => {
  // The builder validates --suite against exactly 8, 9 and 10 for this family.
  it("offers only releases the builder accepts", () => {
    expect(RPM_SUITES.every((v) => ["8", "9", "10"].includes(v))).toBe(true);
  });

  it("puts the newest first, so the default choice is the current one", () => {
    expect(RPM_SUITES[0]).toBe("10");
  });
});
