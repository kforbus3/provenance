import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";

import { ContainerUpdatesTab } from "./ContainerUpdatesTab";
import { useAuthStore } from "../store/auth";

// This tab listed every image the fleet runs. On the deployment this was reported
// from that was 52 rows, six of which were upgradable; the rest read "built
// locally", "upgraded by bundle" or "up to date" — answers to a question nobody
// opens this tab to ask.
//
// So the default is now the actionable rows. The full list stays one click away,
// because it is how you tell "nothing to upgrade" from "never checked".

vi.mock("../api/containerUpdates", () => ({
  listContainerUpdates: vi.fn(),
  checkContainerUpdates: vi.fn(),
}));

import { listContainerUpdates } from "../api/containerUpdates";

const HOST = { hostId: "h1", hostname: "control01", stale: false, protected: false };
const SELF = { hostId: "h1", hostname: "control01", stale: false, protected: true };

function row(repository: string, tag: string, status: string, extra: object = {}) {
  return {
    repository, tag, status, latestTag: "", note: "",
    checkedAt: "2026-09-20T14:29:00Z", hosts: [HOST], ...extra,
  } as never;
}

function renderTab() {
  useAuthStore.setState({
    user: { id: "1", username: "keith" },
    permissions: ["Host.Scan", "Command.Run"],
    isSuperAdmin: true, loaded: true, restore: vi.fn(),
  } as never);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><ContainerUpdatesTab /></QueryClientProvider>,
  );
}

describe("the Updates tab shows what can be upgraded", () => {
  beforeEach(() => vi.mocked(listContainerUpdates).mockReset());

  it("hides up-to-date, locally built and Provenance's own images by default", async () => {
    vi.mocked(listContainerUpdates).mockResolvedValue([
      row("lscr.io/linuxserver/jackett", "v0.24.2624-ls33", "update",
          { latestTag: "v0.24.2627-ls34" }),
      row("nginx", "1.31-alpine", "current"),
      row("provenance-backend", "1.9.10", "local"),
      row("provenance-frontend", "1.9.10", "local", { hosts: [SELF] }),
      row("redis", "8-alpine", "current"),
    ]);
    renderTab();

    await waitFor(() => expect(screen.getByText(/jackett/)).toBeInTheDocument());
    // The noise the complaint was about.
    expect(screen.queryByText(/nginx/)).not.toBeInTheDocument();
    expect(screen.queryByText(/redis/)).not.toBeInTheDocument();
    expect(screen.queryByText(/provenance-backend/)).not.toBeInTheDocument();
  });

  it("keeps a major-version bump, which is available even though a rollout cannot apply it", async () => {
    vi.mocked(listContainerUpdates).mockResolvedValue([
      row("postgres", "17.11-alpine", "migration", { latestTag: "18.6-alpine" }),
      row("nginx", "1.31-alpine", "current"),
    ]);
    renderTab();
    await waitFor(() => expect(screen.getByText(/postgres/)).toBeInTheDocument());
    expect(screen.queryByText(/nginx/)).not.toBeInTheDocument();
  });

  it("keeps images it could not check, so an empty list never means 'we do not know'", async () => {
    vi.mocked(listContainerUpdates).mockResolvedValue([
      row("ghcr.io/private/thing", "v1", "error", { error: "unauthorized" }),
      row("nginx", "1.31-alpine", "current"),
    ]);
    renderTab();
    await waitFor(() =>
      expect(screen.getByText(/private\/thing/)).toBeInTheDocument());
    expect(screen.queryByText(/nginx/)).not.toBeInTheDocument();
  });

  it("shows everything when asked", async () => {
    vi.mocked(listContainerUpdates).mockResolvedValue([
      row("lscr.io/linuxserver/jackett", "v0.24.2624-ls33", "update",
          { latestTag: "v0.24.2627-ls34" }),
      row("nginx", "1.31-alpine", "current"),
      row("provenance-backend", "1.9.10", "local"),
    ]);
    renderTab();
    await waitFor(() => expect(screen.getByText(/jackett/)).toBeInTheDocument());
    expect(screen.queryByText(/nginx/)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("checkbox"));

    await waitFor(() => expect(screen.getByText(/nginx/)).toBeInTheDocument());
    expect(screen.getByText(/provenance-backend/)).toBeInTheDocument();
    // And the label says how many, so the switch explains itself.
    expect(screen.getByText(/All 3 images/)).toBeInTheDocument();
  });
});
