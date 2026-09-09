import { describe, expect, it } from "vitest";
import { PLAYBOOK_TEMPLATES } from "./playbook-templates";

// The A/B template exists twice: as a file that can be syntax-checked and run by
// ansible, and as a string the UI hands to the editor. Two copies drift, and the
// drift is invisible — the file keeps passing its checks while the template the
// UI actually offers is the stale one. So pin them together.
// Equality with deploy/playbooks/ab-update.yml is checked in
// deploy/builder-runner/test_playbook_template.py, not here: `make
// frontend-test` mounts only frontend/, so a check for the file would be
// comparing against something the container cannot see — a test that cannot
// fail. What is checked here is that the template still says what it must.
describe("playbook templates", () => {
  it("offers a blank starter first, so the default is not a specialised playbook", () => {
    expect(PLAYBOOK_TEMPLATES[0].id).toBe("blank");
    expect(PLAYBOOK_TEMPLATES[0].name).toBe("");
  });

  // Each of these is a decision the template exists to encode. A rewrite that
  // drops one produces a playbook that still runs and is still wrong.
  it("the A/B template treats a fallback reboot as a failure", () => {
    const c = PLAYBOOK_TEMPLATES.find((t) => t.id === "ab-update")!.content;
    // GRUB falling back to the old slot means the new slot did not boot. A
    // playbook that reports that as success is worse than no playbook.
    expect(c).toContain("slot_after == slot_before");
    expect(c).toContain("ansible.builtin.fail");
  });

  it("the A/B template does not reboot unless asked", () => {
    const c = PLAYBOOK_TEMPLATES.find((t) => t.id === "ab-update")!.content;
    expect(c).toMatch(/reboot_after:\s*false/);
    expect(c).toContain("when: reboot_after | bool");
  });

  it("the A/B template refuses hosts that are not A/B", () => {
    const c = PLAYBOOK_TEMPLATES.find((t) => t.id === "ab-update")!.content;
    expect(c).toContain("/usr/local/sbin/ab-update");
    expect(c).toContain("not ab_update_bin.stat.exists");
  });

  // The bug this pins cost a real templating error: regex_search returns None
  // rather than undefined when the cmdline has no rauc.slot, and default()
  // replaces undefined only — so first() was handed None and the play died with
  // "'NoneType' object is not iterable" on exactly the machine the 'unknown'
  // branch was written for.
  it("the A/B template survives a cmdline with no rauc.slot", () => {
    const c = PLAYBOOK_TEMPLATES.find((t) => t.id === "ab-update")!.content;
    const searches = c.match(/regex_search\('rauc[^\n]*/g) ?? [];
    expect(searches.length).toBeGreaterThan(0);
    for (const s of searches) {
      expect(s).toContain("default([], true) | first");
    }
  });
});
