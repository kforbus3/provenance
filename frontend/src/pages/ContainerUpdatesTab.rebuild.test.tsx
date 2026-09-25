import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { RebuiltChip } from "./ContainerUpdatesTab";
import type { RebuildDiff } from "../api/containerUpdates";

// "rebuilt" alone could not tell a base-image security fix from a republish that
// installs the same 71 packages at the same versions (nginx:alpine, 2026-09-22).
function diff(extra: Partial<RebuildDiff> = {}): RebuildDiff {
  return {
    ready: true, fromDigest: "sha256:old", toDigest: "sha256:new",
    changed: [], added: [], removed: [],
    before: { critical: 0, high: 1, total: 10 }, after: { critical: 0, high: 1, total: 10 },
    fixed: 0, introduced: 0, ...extra,
  };
}

describe("what a rebuild changed", () => {
  it("says when a rebuild changed nothing installed", () => {
    render(<RebuiltChip d={diff()} />);
    expect(screen.getByText("rebuilt — no package changes")).toBeInTheDocument();
  });

  it("leads with the vulnerabilities a rebuild fixes", () => {
    render(<RebuiltChip d={diff({
      changed: [{ name: "libssl3", type: "apk", from: "3.5.8-r0", to: "3.5.9-r0" }],
      after: { critical: 0, high: 0, total: 8 }, fixed: 2,
    })} />);
    expect(screen.getByText("rebuilt — fixes 2 vulnerabilities")).toBeInTheDocument();
  });

  it("counts changed packages when nothing was fixed", () => {
    render(<RebuiltChip d={diff({ changed: [{ name: "tzdata", type: "apk", from: "2026a", to: "2026b" }] })} />);
    expect(screen.getByText("rebuilt — 1 package changed")).toBeInTheDocument();
  });

  it("does not claim 'no changes' before both builds are scanned", () => {
    render(<RebuiltChip d={diff({ ready: false, reason: "the new build has not been scanned for its packages yet" })} />);
    expect(screen.getByText("rebuilt — comparing…")).toBeInTheDocument();
    expect(screen.queryByText(/no package changes/)).not.toBeInTheDocument();
  });

  it("falls back to plain 'rebuilt' when there is no comparison at all", () => {
    render(<RebuiltChip />);
    expect(screen.getByText("rebuilt")).toBeInTheDocument();
  });
});
