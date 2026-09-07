import { describe, expect, it } from "vitest";
import { invalidPaths, WRITABLE_STATE_DEFAULT } from "./writable-state";

// The builder SKIPS a path directive that is not absolute rather than refusing
// it — see the `if path.startswith("/")` in build_image_cmd. So a typo is a
// setting that appears to have been accepted and is simply not in the image, and
// is discovered on a machine. Cheaper to refuse in the dialog.
describe("invalidPaths", () => {
  it("accepts absolute paths", () => {
    expect(invalidPaths("/home /var/log /opt/app")).toEqual([]);
  });

  it("flags anything the builder would skip", () => {
    expect(invalidPaths("home")).toEqual(["home"]);
    expect(invalidPaths("/home var/log")).toEqual(["var/log"]);
    expect(invalidPaths("./rel ../up ~/tilde")).toEqual(["./rel", "../up", "~/tilde"]);
  });

  it("treats any run of whitespace as the separator, like the builder's split()", () => {
    expect(invalidPaths("/a\n/b\t/c   /d")).toEqual([]);
    expect(invalidPaths("/a\nbad\t/c")).toEqual(["bad"]);
  });

  it("is empty for an empty field, so an unset directive is not an error", () => {
    expect(invalidPaths("")).toEqual([]);
    expect(invalidPaths("   ")).toEqual([]);
    expect(invalidPaths("\n\t ")).toEqual([]);
  });
});

describe("WRITABLE_STATE_DEFAULT", () => {
  // The default has to be what an image with no manifest already gets: one
  // overlay over the whole root, one upper shared by both slots. Anything else
  // would change the behaviour of every build that does not touch this section.
  it("is the historical behaviour", () => {
    expect(WRITABLE_STATE_DEFAULT.stateModel).toBe("overlay");
    expect(WRITABLE_STATE_DEFAULT.slotPrivateUpper).toBe(false);
  });

  it("sets no path directives", () => {
    const { stateModel, slotPrivateUpper, ...paths } = WRITABLE_STATE_DEFAULT;
    void stateModel; void slotPrivateUpper;
    expect(Object.values(paths).every((v) => v === "")).toBe(true);
  });

  // Every directive the builder understands must have a field, or it is a
  // capability with no way to reach it — which is the whole reason for this pass.
  it("covers every path directive the builder takes", () => {
    for (const k of ["persistPaths", "slotPrivatePaths", "volatilePaths",
                     "resetPaths", "keepPaths", "ownPaths"]) {
      expect(WRITABLE_STATE_DEFAULT, k).toHaveProperty(k);
    }
  });
});
