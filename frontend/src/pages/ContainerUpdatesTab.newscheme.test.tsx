import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ContainerUpdatesTab, verdictOf } from "./ContainerUpdatesTab";
import { useAuthStore } from "../store/auth";

// jellyfin 10.11.11 read "up to date" for seven weeks with 12.0–12.4 published:
// the project now numbers releases with two components, so no tag of the running
// shape will ever be newer. It was hidden from the default view, and nothing else
// on the page said so.

vi.mock("../api/containerUpdates", () => ({
  listContainerUpdates: vi.fn(),
  checkContainerUpdates: vi.fn(),
}));

import { listContainerUpdates } from "../api/containerUpdates";

const HOST = { hostId: "h1", hostname: "docker", stale: false, protected: false };

const jellyfin = {
  repository: "jellyfin/jellyfin", tag: "10.11.11", status: "newscheme",
  newerElsewhere: "12.4",
  note: "12.4 is published under a different tag format than 10.11.11, so it cannot be rolled out from here; change the pin to move to it",
  checkedAt: "2026-10-27T14:00:00Z", hosts: [HOST],
};
const headlamp = {
  repository: "ghcr.io/headlamp-k8s/headlamp", tag: "v0.43.0", latestTag: "v0.45.0",
  status: "update", checkedAt: "2026-10-27T14:00:00Z", hosts: [HOST],
};

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

describe("a later release under a different tag format", () => {
  beforeEach(() => {
    vi.mocked(listContainerUpdates).mockResolvedValue([jellyfin, headlamp] as never);
  });

  it("is its own verdict, not 'current' and not 'newer'", () => {
    expect(verdictOf(jellyfin as never, [jellyfin as never])).toBe("newscheme");
  });

  it("is shown in the default view, naming the release", async () => {
    renderTab();
    await waitFor(() => expect(screen.getByText("12.4 — new tag format")).toBeInTheDocument());
  });

  it("offers no Roll out and is left out of the count", async () => {
    renderTab();
    await waitFor(() => expect(screen.getByText(/1 image has a newer version\./i)).toBeInTheDocument());
    // Only headlamp can be rolled out. A button here would move a host to
    // whatever the row named, across a numbering scheme, as a routine update.
    expect(screen.getAllByText("Roll out")).toHaveLength(1);
  });
});
