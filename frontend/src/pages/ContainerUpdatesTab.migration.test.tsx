import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ContainerUpdatesTab, verdictOf } from "./ContainerUpdatesTab";
import { useAuthStore } from "../store/auth";

// This fleet's Updates page offered postgres 16-alpine → 18-alpine as an ordinary
// update. A rollout refuses it — correctly, because the new binary reads the old
// data directory, refuses it, and restarts forever — but the refusal rejects the
// WHOLE request. So one impossible row sat in "roll out everything" and blocked the
// two real updates behind it, and the "available" count could never reach zero.

vi.mock("../api/containerUpdates", () => ({
  listContainerUpdates: vi.fn(),
  checkContainerUpdates: vi.fn(),
}));

import { listContainerUpdates } from "../api/containerUpdates";

const HOST = { hostId: "h1", hostname: "control01", stale: false, protected: false };

function update(repository: string, tag: string, latestTag: string, status: string) {
  return {
    repository, tag, latestTag, status,
    checkedAt: "2026-09-19T14:29:00Z",
    note: status === "migration" ? "crosses a major version … needs pg_upgrade first" : "",
    hosts: [HOST],
  } as never;
}

function renderTab() {
  useAuthStore.setState({
    user: { id: "1", username: "alice" },
    permissions: ["Host.Scan", "Command.Run"],
    isSuperAdmin: true, loaded: true, restore: vi.fn(),
  } as never);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><ContainerUpdatesTab /></QueryClientProvider>,
  );
}

describe("an update a rollout can never apply", () => {
  beforeEach(() => {
    vi.mocked(listContainerUpdates).mockResolvedValue([
      update("postgres", "16-alpine", "18-alpine", "migration"),
      update("ghcr.io/headlamp-k8s/headlamp", "v0.43.0", "v0.45.0", "update"),
    ]);
  });

  it("is its own verdict, not 'newer'", () => {
    expect(verdictOf(update("postgres", "16-alpine", "18-alpine", "migration") as never)).toBe("migration");
    expect(verdictOf(update("nginx", "1.24", "1.27", "update") as never)).toBe("newer");
  });

  it("is shown as a migration and offers no Roll out button", async () => {
    renderTab();
    await waitFor(() => expect(screen.getByText(/migration, not an update/)).toBeInTheDocument());
    // Exactly one row is actionable: the headlamp one.
    expect(screen.getAllByText("Roll out")).toHaveLength(1);
  });

  it("is left out of the count of what is available", async () => {
    renderTab();
    // One, not two: counting an update nobody can apply means the number never
    // reaches zero however much work the operator does.
    await waitFor(() => expect(screen.getByText(/1 image has a newer version\./i)).toBeInTheDocument());
  });
});
