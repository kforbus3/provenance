import { describe, expect, it } from "vitest";
import { imageSoakStatus, type RolloutImage } from "./containerUpdates";

const im = (p: Partial<RolloutImage>): RolloutImage => ({ repository: "nginx", fromTag: "1", toTag: "2", ...p });
const now = new Date("2026-10-01T12:10:00Z");

describe("imageSoakStatus", () => {
  it("walks an image through its own canary and soak", () => {
    const r = { canary: 1, soakSeconds: 300 };
    expect(imageSoakStatus(im({}), r, now)).toBe("proving on its canary");
    expect(imageSoakStatus(im({ canaryDoneAt: "2026-10-01T12:08:00Z" }), r, now)).toMatch(/^soaking until /);
    expect(imageSoakStatus(im({ canaryDoneAt: "2026-10-01T12:00:00Z" }), r, now)).toBe("re-checking the canary");
    expect(imageSoakStatus(im({ canaryDoneAt: "2026-10-01T12:00:00Z", soakCheckedAt: "2026-10-01T12:05:10Z" }), r, now))
      .toBe("soak passed");
  });
  it("says so when there is no soak or no canary", () => {
    expect(imageSoakStatus(im({ canaryDoneAt: "2026-10-01T12:00:00Z" }), { canary: 1, soakSeconds: 0 }, now))
      .toBe("canary verified");
    expect(imageSoakStatus(im({}), { canary: 0, soakSeconds: 300 }, now)).toBe("no canary");
  });
});
