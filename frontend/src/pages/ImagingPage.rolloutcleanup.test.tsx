import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { RolloutsTab } from "./ImagingPage";
import * as imagingApi from "../api/imaging";
import * as adminApi from "../api/admin";

// Finished rollouts accumulated on the page with no way to clear them, so the
// one actually running was buried under a month of history.
//
// The API route and the store function existed the whole time; only the button
// was missing — and the API client wrapper for it was deleted in a dead-code
// sweep as "unused", which is exactly what unused means for a feature whose UI
// was never built. Deleting the wrapper hid the gap rather than closing it.

vi.mock("../api/imaging", async () => {
  const actual = await vi.importActual<typeof imagingApi>("../api/imaging");
  return { ...actual, deleteRollout: vi.fn(), listBundles: vi.fn(), listMachines: vi.fn() };
});
vi.mock("../api/admin", async () => {
  const actual = await vi.importActual<typeof adminApi>("../api/admin");
  return { ...actual, listGroups: vi.fn() };
});

function rollout(id: string, state: string) {
  return {
    id, state, version: `1.0.${id}`, bundle: "b.raucb",
    targetAll: true, targetGroups: [], targetHosts: [],
    done: 1, total: 1, counts: {}, canary: 1, batchSize: 10,
    soakSeconds: 900, maxFailures: 2,
  } as unknown as imagingApi.Rollout;
}

function renderTab(rollouts: imagingApi.Rollout[], canManage = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <RolloutsTab rollouts={rollouts} canManage={canManage}
                   onSteer={() => {}} onCreated={() => {}} setMsg={() => {}} />
    </QueryClientProvider>,
  );
}

describe("clearing finished rollouts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(adminApi.listGroups).mockResolvedValue([] as never);
    vi.mocked(imagingApi.deleteRollout).mockResolvedValue(undefined as never);
    vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  it("offers to clear finished rollouts, counting them", async () => {
    renderTab([rollout("1", "completed"), rollout("2", "failed"), rollout("3", "running")]);
    expect(await screen.findByRole("button", { name: /clear finished \(2\)/i })).toBeInTheDocument();
  });

  it("clears every finished rollout and leaves the running one alone", async () => {
    renderTab([rollout("1", "completed"), rollout("2", "cancelled"), rollout("3", "running")]);
    fireEvent.click(await screen.findByRole("button", { name: /clear finished/i }));
    await waitFor(() => expect(imagingApi.deleteRollout).toHaveBeenCalledTimes(2));
    const cleared = vi.mocked(imagingApi.deleteRollout).mock.calls.map((c) => c[0]);
    expect(cleared.sort()).toEqual(["1", "2"]);
    expect(cleared).not.toContain("3");
  });

  // The server refuses to delete a running rollout — cancel it first. Offering a
  // button that is going to be refused teaches people to distrust the buttons.
  it("does not offer to remove a rollout that is still running", () => {
    renderTab([rollout("3", "running")]);
    expect(screen.queryByRole("button", { name: /clear finished/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /remove from the list/i })).toBeNull();
  });

  it("hides the whole thing from someone who cannot manage imaging", () => {
    renderTab([rollout("1", "completed")], false);
    expect(screen.queryByRole("button", { name: /clear finished/i })).toBeNull();
  });
});
