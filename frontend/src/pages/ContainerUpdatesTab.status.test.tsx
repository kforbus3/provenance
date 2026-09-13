import "@testing-library/jest-dom/vitest";
import { describe, it, expect } from "vitest";
import { verdictOf } from "./ContainerUpdatesTab";
import type { ImageUpdate } from "../api/containerUpdates";

// Twenty-two healthy images read as "cannot compare" because the verdict was
// inferred from the NOTE, and this sentence —
//
//   "nothing newer with the same shape as 10.11.11; the repository carries
//    other version tags that cannot be ordered against it"
//
// — means up to date. It rendered identically to a check that failed. Prose is
// not an API; that text changed twice in one evening.
function row(extra: Partial<ImageUpdate> = {}): ImageUpdate {
  return {
    repository: "jellyfin/jellyfin", tag: "10.11.11",
    checkedAt: "2026-09-13T03:00:00Z",
    hosts: [{ hostId: "h1", hostname: "docker", digest: "sha256:a" }],
    ...extra,
  } as ImageUpdate;
}

describe("verdict comes from the status, not the prose", () => {
  it("reads 'checked and current' as current, not as a failed check", () => {
    const u = row({
      status: "current",
      note: "nothing newer with the same shape as 10.11.11; the repository "
        + "carries other version tags that cannot be ordered against it",
    });
    expect(verdictOf(u, [u])).toBe("current");
    expect(verdictOf(u, [u])).not.toBe("unknown");
  });

  it("keeps 'cannot compare' for a repository with nothing comparable", () => {
    const u = row({ status: "unorderable", note: "no tag in this repository has the same shape" });
    expect(verdictOf(u, [u])).toBe("unknown");
  });

  it("separates a registry that would not answer from one that did", () => {
    const u = row({ status: "unavailable", note: "could not list tags: the registry is rate limiting" });
    expect(verdictOf(u, [u])).toBe("unavailable");
  });

  it("still reads an update and a rebuild", () => {
    const up = row({ status: "update", latestTag: "10.12.0" });
    const moved = row({ status: "moved", note: "tag moved: rebuilt at the same version" });
    expect(verdictOf(up, [up])).toBe("newer");
    expect(verdictOf(moved, [moved])).toBe("moved");
  });

  it("falls back to the note for rows written before status existed", () => {
    // An upgrade must not blank the page while it waits for the next check.
    const local = row({ note: "built locally — no registry digest on any host" });
    const upd = row({ latestTag: "10.12.0" });
    expect(verdictOf(local, [local])).toBe("local");
    expect(verdictOf(upd, [upd])).toBe("newer");
  });

  it("lets superseded win over the status", () => {
    // The running row is not actionable however the registry answered: the
    // host's compose has moved past it.
    const running = row({ tag: "latest", status: "moved" });
    const declared = row({ tag: "10.11.11", declared: true, status: "update", latestTag: "10.12.0" });
    expect(verdictOf(running, [running, declared])).toBe("superseded");
  });
});
