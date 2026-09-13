import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// An evening of one-image rollouts leaves thirty finished rows above the one
// that is actually running. A rollout that is over is history, not state.
vi.mock("../api/containerUpdates", async () => {
  const actual = await vi.importActual<typeof import("../api/containerUpdates")>(
    "../api/containerUpdates");
  return { ...actual, listRollouts: vi.fn(), clearFinishedRollouts: vi.fn(), getRollout: vi.fn() };
});
import { listRollouts, clearFinishedRollouts, type UpdateRollout } from "../api/containerUpdates";
import { RolloutsTab } from "./RolloutsTab";
import { useAuthStore } from "../store/auth";

function rollout(id: string, state: string): UpdateRollout {
  return {
    id, state, repository: "team/app", fromTag: "1.0.0", toTag: "1.1.0",
    canary: 1, batchSize: 5, soakSeconds: 0, maxFailures: 1,
    createdAt: "2026-09-13T02:00:00Z", hosts: [],
  } as unknown as UpdateRollout;
}

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><RolloutsTab /></QueryClientProvider>);
}

describe("clearing finished rollouts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({ permissions: ["Command.Run"] } as never);
  });
  afterEach(() => vi.restoreAllMocks());

  it("offers to clear only the rollouts that are over", async () => {
    vi.mocked(listRollouts).mockResolvedValue([
      rollout("a", "completed"), rollout("b", "cancelled"),
      rollout("c", "halted"), rollout("d", "running"),
      rollout("e", "paused"),
    ]);
    renderTab();
    // completed + cancelled + halted = 3. Running is live; paused only LOOKS
    // inert — resume is a button somebody may still intend to press.
    expect(await screen.findByRole("button", { name: /clear finished \(3\)/i })).toBeInTheDocument();
  });

  it("does not offer the button when nothing has finished", async () => {
    vi.mocked(listRollouts).mockResolvedValue([rollout("d", "running")]);
    renderTab();
    await screen.findByText(/staged rollouts/i);
    expect(screen.queryByRole("button", { name: /clear finished/i })).not.toBeInTheDocument();
  });

  it("clears in one request, not one per rollout", async () => {
    vi.mocked(listRollouts).mockResolvedValue([
      rollout("a", "completed"), rollout("b", "completed"), rollout("c", "completed"),
    ]);
    vi.mocked(clearFinishedRollouts).mockResolvedValue({ deleted: 3 });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderTab();

    fireEvent.click(await screen.findByRole("button", { name: /clear finished \(3\)/i }));

    await waitFor(() => expect(clearFinishedRollouts).toHaveBeenCalledTimes(1));
  });

  it("asks before removing anything", async () => {
    vi.mocked(listRollouts).mockResolvedValue([rollout("a", "completed")]);
    const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
    renderTab();

    fireEvent.click(await screen.findByRole("button", { name: /clear finished \(1\)/i }));

    expect(confirm).toHaveBeenCalled();
    expect(clearFinishedRollouts).not.toHaveBeenCalled();
  });
});
