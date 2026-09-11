import { describe, expect, it } from "vitest";
import { combinationProblems, invalidPaths, WRITABLE_STATE_DEFAULT } from "./writable-state";

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

// A keep is a carve-out from a reset and only from a reset. build-image.sh
// refuses these outright; this is the same rule in the dialog so the answer
// arrives before a thirty-minute build rather than after it.
//
// deploy/builder-runner/test_state_model_guards.py checks this file's copy of
// the reset lists against what the builder actually reports, so the two cannot
// drift apart without something failing.
describe("combinationProblems", () => {
  const v = (over: Partial<typeof WRITABLE_STATE_DEFAULT>) =>
    ({ ...WRITABLE_STATE_DEFAULT, ...over });

  it("passes the default, which keeps nothing", () => {
    expect(combinationProblems(WRITABLE_STATE_DEFAULT)).toEqual([]);
  });

  // The one that matters: keeping /usr cancels the reset that lets an update be
  // seen at all, so the machine runs the old release and reports success.
  it("refuses keeping a path that is itself reset", () => {
    const p = combinationProblems(v({ keepPaths: "/usr" }));
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("cancels the reset");
  });

  it("refuses keeping the package database of either family", () => {
    expect(combinationProblems(v({ keepPaths: "/var/lib/dpkg" }))).toHaveLength(1);
    expect(combinationProblems(v({ keepPaths: "/var/lib/rpm" }))).toHaveLength(1);
  });

  it("refuses a keep that carves nothing out", () => {
    const p = combinationProblems(v({ keepPaths: "/opt" }));
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("does nothing");
  });

  it("accepts a keep inside something the model resets", () => {
    expect(combinationProblems(v({ keepPaths: "/usr/local" }))).toEqual([]);
  });

  it("accepts a keep inside something the operator resets", () => {
    expect(combinationProblems(v({
      resetPaths: "/srv", keepPaths: "/srv/keepme",
    }))).toEqual([]);
  });

  // The models reset different things, so the same keep is right under one and
  // meaningless under another. stateful does not reset /usr at all.
  it("judges a keep against the selected model", () => {
    expect(combinationProblems(v({ keepPaths: "/usr/local" }))).toEqual([]);
    expect(combinationProblems(v({
      stateModel: "stateful", keepPaths: "/usr/local",
    }))).toHaveLength(1);
  });

  it("reports every bad keep, not just the first", () => {
    expect(combinationProblems(v({ keepPaths: "/usr /opt" }))).toHaveLength(2);
  });

  // Already reported by invalidPaths; saying it twice in two different ways
  // reads as two separate problems.
  it("leaves non-absolute paths to invalidPaths", () => {
    expect(combinationProblems(v({ keepPaths: "relative" }))).toEqual([]);
  });

  // The builder adds this itself when an encrypted image resets /etc, so the
  // dialog must not flag the value the builder is about to supply.
  it("does not flag the LUKS enrollment keep the builder adds", () => {
    expect(combinationProblems(v({
      keepPaths: "/etc/cryptsetup-keys.d",
    }))).toEqual([]);
  });

  // A prefix match on the string alone would treat /usr-backup as inside /usr.
  it("matches on path components, not string prefixes", () => {
    const p = combinationProblems(v({ keepPaths: "/usrlocal" }));
    expect(p).toHaveLength(1);
    expect(p[0]).toContain("does nothing");
  });
});
