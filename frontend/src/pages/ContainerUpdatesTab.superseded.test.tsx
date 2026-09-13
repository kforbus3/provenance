import "@testing-library/jest-dom/vitest";
import { describe, it, expect } from "vitest";
import { supersededBy, verdictOf } from "./ContainerUpdatesTab";
import type { ImageUpdate } from "../api/containerUpdates";

// The state six services were actually in.
//
// The container runs :latest. The compose file names v1.6.0-ls356. That makes
// two rows, and they behave in OPPOSITE ways:
//
//   - rolling out :latest can only skip, because the host's compose has moved
//     past :latest, so the container is never recreated and the row reports
//     "rebuilt" again on the next check, forever;
//   - rolling out v1.6.0-ls356 rewrites the file, recreates the container, and
//     is what finally moves it off :latest.
//
// The rebuild row was the only one shown. It was rolled out. The rollout
// completed successfully and changed nothing.
const host = { hostId: "h1", hostname: "docker", digest: "sha256:old", stale: true };

function row(tag: string, extra: Partial<ImageUpdate> = {}): ImageUpdate {
  return {
    repository: "lscr.io/linuxserver/bazarr",
    tag,
    checkedAt: "2026-09-13T01:32:00Z",
    hosts: [host],
    ...extra,
  } as ImageUpdate;
}

describe("a running tag superseded by a compose file", () => {
  const running = row("latest");
  const declared = row("v1.6.0-ls356", { declared: true, latestTag: "v1.6.0-ls363" });
  const all = [running, declared];

  it("names the row that can actually be applied", () => {
    expect(supersededBy(running, all)?.tag).toBe("v1.6.0-ls356");
  });

  it("does not offer the rebuild as actionable", () => {
    // Without this it reads "rebuilt", which invites the rollout that does
    // nothing — and reports success for it.
    expect(verdictOf(running, all)).toBe("superseded");
    expect(verdictOf(running, all)).not.toBe("moved");
  });

  it("leaves the declared row actionable", () => {
    expect(verdictOf(declared, all)).toBe("newer");
  });

  it("still reports a genuine rebuild when nothing supersedes it", () => {
    // A host running :latest with no compose file naming anything else. The
    // rebuild is real and applying it works.
    const lone = row("latest");
    expect(verdictOf(lone, [lone])).toBe("moved");
  });

  it("does not treat a declared row as superseding itself", () => {
    expect(supersededBy(declared, all)).toBeUndefined();
  });

  it("does not cross repositories", () => {
    const other = { ...row("v2.0.0"), repository: "other/app", declared: true } as ImageUpdate;
    expect(supersededBy(running, [running, other])).toBeUndefined();
  });
});
