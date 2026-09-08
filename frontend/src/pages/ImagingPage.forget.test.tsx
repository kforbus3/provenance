import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { MachinesTab } from "./ImagingPage";
import * as imagingApi from "../api/imaging";

// Forgetting a machine, end to end through the UI.
//
// The bug this pins shipped as a button that did nothing. The route, the store
// function, the API client, the mutation and the button all existed and were
// correct — and the confirmation dialog that the button opens was never added to
// the tree. Clicking it set some state and rendered nothing.
//
// Nothing else could catch that. TypeScript was happy: the state and the
// mutation are both real and both used. The linter was happy. The bundle even
// contained the button. It is only wrong when someone clicks it, and the symptom
// is silence, which reads as a backend problem rather than a missing element.
//
// So the test drives the actual sequence: the button is there, clicking it opens
// a confirmation, and confirming calls the API with that machine's id.

vi.mock("../api/imaging", async () => {
  const actual = await vi.importActual<typeof imagingApi>("../api/imaging");
  return {
    ...actual,
    deleteMachine: vi.fn(),
    listBundles: vi.fn(),
  };
});

function machine(id: string, hostname: string) {
  return {
    id, hostname, address: "192.168.50.160", slot: "A", version: "1.0",
    image: "almalinux-9-amd64-ab.img.zst", arch: "amd64", agentVersion: "1",
    label: "", held: false, hostId: null, reachable: false, presence: "unknown",
    lastSeen: new Date().toISOString(),
  } as unknown as Parameters<typeof MachinesTab>[0]["fleet"] extends undefined ? never : never;
}

function renderTab(canManage = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const fleet = {
    machines: [machine("bc:24:11:fd:c8:c0", "alma1")],
    versions: { "1.0": 1 },
    counts: { total: 1, online: 0, offline: 1, unknown: 0 },
  } as unknown as Awaited<ReturnType<typeof imagingApi.listMachines>>;
  return render(
    <QueryClientProvider client={qc}>
      <MachinesTab fleet={fleet} canManage={canManage} onNudge={() => {}} busy={false}
                   onDone={() => {}} setMsg={() => {}} />
    </QueryClientProvider>,
  );
}

describe("forgetting a machine", () => {
  beforeEach(() => {
    vi.mocked(imagingApi.listBundles).mockResolvedValue({
      bundles: [], controlUrl: "",
    } as unknown as Awaited<ReturnType<typeof imagingApi.listBundles>>);
    vi.mocked(imagingApi.deleteMachine).mockResolvedValue(undefined);
  });

  it("offers a Forget button for an operator who can manage", () => {
    renderTab(true);
    expect(screen.getByRole("button", { name: /forget/i })).toBeInTheDocument();
  });

  it("opens a confirmation rather than deleting on the first click", async () => {
    renderTab(true);
    fireEvent.click(screen.getByRole("button", { name: /^forget$/i }));
    // The dialog is the part that was missing: the button set state and nothing
    // rendered, so the click was silent and nothing was ever deleted.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: /forget it/i })).toBeInTheDocument());
    expect(imagingApi.deleteMachine).not.toHaveBeenCalled();
  });

  it("calls the API with that machine's id once confirmed", async () => {
    renderTab(true);
    fireEvent.click(screen.getByRole("button", { name: /^forget$/i }));
    await waitFor(() => screen.getByRole("button", { name: /forget it/i }));
    fireEvent.click(screen.getByRole("button", { name: /forget it/i }));
    await waitFor(() =>
      expect(imagingApi.deleteMachine).toHaveBeenCalledWith("bc:24:11:fd:c8:c0"));
  });

  it("does not offer it to someone who cannot manage imaging", () => {
    renderTab(false);
    expect(screen.queryByRole("button", { name: /forget/i })).not.toBeInTheDocument();
  });
});
