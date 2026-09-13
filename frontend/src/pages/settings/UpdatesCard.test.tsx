import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { UpdatesCard } from "./UpdatesCard";

// Three applies in sixteen seconds.
//
//   13:34:43  system.upgrade_apply  1.2.4
//   13:34:50  system.upgrade_apply  1.2.4
//   13:34:59  system.upgrade_apply  1.2.4
//
// The status endpoint reports the PREVIOUS run until the updater picks the new
// job up. So: dispatch, spinner, one poll later the stale "success" for the OLD
// version arrives, `active` goes false, the spinner vanishes and Install comes
// back. The success banner is correctly suppressed (it names a version this page
// did not dispatch), so the screen shows nothing at all — and the button gets
// pressed again.

vi.mock("../../api/upgrade", () => ({
  getVersion: vi.fn().mockResolvedValue({ version: "1.2.3" }),
  checkForUpdate: vi.fn().mockResolvedValue({ channelEnabled: false, updateAvailable: false }),
  previewUpgrade: vi.fn(),
  applyUpgrade: vi.fn(),
  pullUpdate: vi.fn(),
  getUpgradeStatus: vi.fn(),
}));

import {
  previewUpgrade, applyUpgrade, getUpgradeStatus,
} from "../../api/upgrade";

async function uploadAndInstall() {
  vi.mocked(previewUpgrade).mockResolvedValue({
    version: "1.2.4", migrationCompatibility: "additive", components: [],
  } as never);
  vi.mocked(applyUpgrade).mockResolvedValue({} as never);

  const { container } = render(<UpdatesCard />);
  const input = container.querySelector('input[type="file"]') as HTMLInputElement;
  const file = new File(["x"], "fleet-1.2.4.provup");
  Object.defineProperty(input, "files", { value: [file] });
  fireEvent.change(input);

  const install = await screen.findByText(/Install 1\.2\.4/);
  fireEvent.click(install);
  return install;
}

describe("UpdatesCard", () => {
  beforeEach(() => { vi.clearAllMocks(); vi.useRealTimers(); });

  it("stays in progress when the status endpoint still reports the previous run", async () => {
    // The stale status: a SUCCESS, for the version that was already installed.
    vi.mocked(getUpgradeStatus).mockResolvedValue({
      state: "success", targetVersion: "1.2.3",
    } as never);

    await uploadAndInstall();

    await waitFor(() => expect(applyUpgrade).toHaveBeenCalledTimes(1));

    // Wait for a real poll to land (the interval is 3s). This is the moment the
    // bug happened: the stale "success" for 1.2.3 arrives and, before the latch,
    // cleared the in-progress UI and brought the Install button back.
    await waitFor(
      () => expect(getUpgradeStatus).toHaveBeenCalled(),
      { timeout: 5000 },
    );

    // A function matcher: the step and the target version are separate text nodes
    // inside one line, so a plain regex sees neither whole.
    await waitFor(() =>
      // getAllByText: the matcher sees ancestors as well as the line itself.
      expect(
        screen.getAllByText((_, el) => !!el?.textContent?.includes("Waiting for the updater")).length,
      ).toBeGreaterThan(0),
    );
    // The button must NOT have come back — that is what got clicked three times.
    expect(screen.queryByText(/Install 1\.2\.4/)).not.toBeInTheDocument();
    // And it must not claim the OLD version succeeded.
    expect(screen.queryByText(/Upgraded to 1\.2\.3/)).not.toBeInTheDocument();
  });

  it("announces success only for the version this page dispatched", async () => {
    vi.mocked(getUpgradeStatus).mockResolvedValue({
      state: "success", targetVersion: "1.2.4",
    } as never);

    await uploadAndInstall();
    await waitFor(() => expect(applyUpgrade).toHaveBeenCalledTimes(1));

    await waitFor(
      () => expect(screen.getByText(/Upgraded to 1\.2\.4/)).toBeInTheDocument(),
      { timeout: 5000 },
    );
  });

  it("keeps polling when the first result names the PREVIOUS version", async () => {
    // The hang, exactly as it happened.
    //
    // At dispatch the status file still held the previous upgrade's `success`
    // for a few seconds, until the updater began writing the new run. The first
    // poll saw success-for-1.2.6, and stopping on ANY terminal state killed the
    // interval. The latch then correctly refused to settle on a version it had
    // not dispatched — and with nothing left polling, waited forever:
    //
    //     Waiting for the updater to pick this up… (→ 1.2.7)
    //
    // while the upgrade to 1.2.7 had in fact already succeeded.
    let poll = 0;
    vi.mocked(getUpgradeStatus).mockImplementation(async () => {
      poll += 1;
      // First answer: the PREVIOUS run, already finished.
      if (poll === 1) return { state: "success", targetVersion: "1.2.6" } as never;
      // Then the real one.
      return { state: "success", targetVersion: "1.2.4-DISPATCHED" } as never;
    });

    // Dispatch 1.2.4-DISPATCHED so the second answer is "ours".
    vi.mocked(previewUpgrade).mockResolvedValue({
      version: "1.2.4-DISPATCHED", migrationCompatibility: "additive", components: [],
    } as never);
    vi.mocked(applyUpgrade).mockResolvedValue({} as never);

    const { container } = render(<UpdatesCard />);
    const input = container.querySelector('input[type="file"]') as HTMLInputElement;
    Object.defineProperty(input, "files", { value: [new File(["x"], "b.provup")] });
    fireEvent.change(input);
    fireEvent.click(await screen.findByText(/Install 1\.2\.4-DISPATCHED/));

    await waitFor(() => expect(applyUpgrade).toHaveBeenCalledTimes(1));

    // If polling stopped on the stale success, this never arrives.
    await waitFor(
      () => expect(screen.getByText(/Upgraded to 1\.2\.4-DISPATCHED/)).toBeInTheDocument(),
      { timeout: 12000 },
    );
    expect(poll).toBeGreaterThan(1);
  }, 20000);
});
