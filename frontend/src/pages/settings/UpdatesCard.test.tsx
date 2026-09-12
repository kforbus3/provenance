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
  const file = new File(["x"], "fleet-1.2.4.fleetup");
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
});
