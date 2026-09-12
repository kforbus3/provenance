import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { DiscoveredProjectsPanel } from "./DiscoveredProjectsPanel";

// The Stacks page listed only ADOPTED stacks, and adoption happened as a side
// effect of a rollout that needed one. So a working deployment showed a single
// row — or none — and read as an empty product with a setup task attached, when
// in fact sixteen compose projects across seven hosts were already discovered and
// most were already updatable.
//
// Nothing here is configured. A compose-managed container records its own project
// and directory, so these are found wherever they live.

vi.mock("../api/stacks", () => ({ listDiscoveredProjects: vi.fn() }));
import { listDiscoveredProjects } from "../api/stacks";

function renderPanel() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><DiscoveredProjectsPanel /></QueryClientProvider>,
  );
}

describe("DiscoveredProjectsPanel", () => {
  beforeEach(() => vi.clearAllMocks());

  it("lists projects from anywhere on the filesystem, adopted or not", async () => {
    vi.mocked(listDiscoveredProjects).mockResolvedValue([
      { hostId: "h1", hostname: "docker", project: "media-stack",
        dir: "/home/keith/media-stack", services: ["sonarr"], images: 14, adopted: false },
      { hostId: "h1", hostname: "docker", project: "nextcloud",
        dir: "/opt/stacks/nextcloud", services: ["app"], images: 5, adopted: false },
      { hostId: "h2", hostname: "repo", project: "aptlywebui",
        dir: "/root/aptlywebui", services: ["aptly"], images: 4, adopted: false },
      { hostId: "h3", hostname: "ai", project: "test2",
        dir: "/home/keith/test2", services: ["ollama"], images: 8, adopted: true,
        stackId: "s1" },
    ] as never);

    renderPanel();

    // No configured location: /home, /opt and /root all appear.
    await waitFor(() =>
      expect(screen.getByText("/home/keith/media-stack")).toBeInTheDocument());
    expect(screen.getByText("/opt/stacks/nextcloud")).toBeInTheDocument();
    expect(screen.getByText("/root/aptlywebui")).toBeInTheDocument();
    expect(screen.getByText("4 compose projects", { exact: false })).toBeInTheDocument();
  });

  it("says plainly that an unadopted project is still updatable", async () => {
    // The whole point. "Not adopted" must not read as "not working" — that
    // misreading is what made this look like a setup chore.
    vi.mocked(listDiscoveredProjects).mockResolvedValue([
      { hostId: "h1", hostname: "docker", project: "media-stack",
        dir: "/home/keith/media-stack", services: ["sonarr"], images: 14, adopted: false },
    ] as never);

    renderPanel();

    await waitFor(() =>
      expect(screen.getByText("updates in place")).toBeInTheDocument());
    expect(screen.getByText(/without adopting anything/i)).toBeInTheDocument();
    // And a low adopted count is explicitly normal, not a backlog.
    expect(screen.getByText(/staying low is normal/i)).toBeInTheDocument();
  });

  it("explains an empty list as timing rather than as nothing to do", async () => {
    vi.mocked(listDiscoveredProjects).mockResolvedValue([] as never);
    renderPanel();
    await waitFor(() =>
      expect(screen.getByText(/discovered by the monitor sweep/i)).toBeInTheDocument());
  });
});
