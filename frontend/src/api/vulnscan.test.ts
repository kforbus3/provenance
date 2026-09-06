import { describe, expect, it } from "vitest";
import { isKernelSourceFinding, vulnComponent, type VulnFinding } from "./vulnscan";

const finding = (over: Partial<VulnFinding>): VulnFinding => ({
  cve: "CVE-2025-40074",
  package: "libcpupower1",
  installedVersion: "6.12.105-1",
  severity: "Critical",
  cvssScore: 9.8,
  ...over,
});

describe("isKernelSourceFinding", () => {
  // The arrangement from a real Debian 13 host: cpupower and its library are built
  // from the `linux` source package that the security tracker files kernel CVEs
  // under, so grype matched 227 critical+high kernel CVEs against them — 41% of the
  // host's total — while the installed linux-image-* packages matched nothing at
  // all. Without this the UI shows a wall of criticals against a CPU-frequency
  // utility and gives the reader no way to know they are kernel bugs.
  it("flags kernel CVEs that landed on userspace helpers", () => {
    for (const pkg of [
      "libcpupower1", "linux-cpupower", "linux-headers-6.12.105+deb13-amd64",
      "linux-kbuild-6.12.105+deb13", "linux-libc-dev", "linux-base",
    ]) {
      expect(isKernelSourceFinding(finding({ package: pkg, sourcePackage: "linux" })), pkg).toBe(true);
    }
  });

  it("leaves the kernel itself alone — it is already attributed correctly", () => {
    for (const pkg of ["linux-image-6.12.105+deb13-amd64", "linux-image-amd64", "kernel-core"]) {
      expect(isKernelSourceFinding(finding({ package: pkg, sourcePackage: "linux" })), pkg).toBe(false);
    }
  });

  it("ignores everything that is not from a kernel source", () => {
    expect(isKernelSourceFinding(finding({ package: "libcurl4t64", sourcePackage: "curl" }))).toBe(false);
    // A scan recorded before source capture knows no source and must not guess from
    // the package name alone.
    expect(isKernelSourceFinding(finding({ package: "libcpupower1" }))).toBe(false);
  });
});

describe("vulnComponent", () => {
  it("reports the source package when one is known", () => {
    expect(vulnComponent(finding({ sourcePackage: "linux" }))).toBe("linux");
  });

  // Scans predating source capture must still group into something meaningful
  // rather than collapsing every finding into one empty-named bucket.
  it("falls back to the binary package when no source was captured", () => {
    expect(vulnComponent(finding({ package: "openssl" }))).toBe("openssl");
    expect(vulnComponent(finding({ package: "openssl", sourcePackage: "   " }))).toBe("openssl");
  });
});
