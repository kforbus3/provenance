import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";

import { UnhealthyContainersBanner } from "./UnhealthyContainersBanner";

// Two containers were crash-looping in this fleet — `wikipedia` on the GPU host
// and `docker-backend-1` on the build host — for long enough that nobody could
// say when they had started. Every part of the machinery worked: the state was
// collected, served, and drawn as an orange chip inside one host's expanded
// detail panel, in a 220-pixel scrolling list. Seeing it required already
// suspecting that host.

vi.mock("../api/stacks", () => ({ listUnhealthyContainers: vi.fn() }));

import { listUnhealthyContainers } from "../api/stacks";

function container(over: Record<string, unknown> = {}) {
  return {
    hostId: "h1", hostname: "ai", name: "wikipedia",
    state: "restarting", status: "Restarting (0) 40 seconds ago",
    composeDir: "/home/keith/test2",
    why: "restarting in a loop — it is not staying up",
    collectedAt: new Date().toISOString(),
    ...over,
  } as never;
}

function renderBanner() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><UnhealthyContainersBanner /></QueryClientProvider>,
  );
}

describe("the unhealthy container banner", () => {
  beforeEach(() => vi.mocked(listUnhealthyContainers).mockReset());

  it("says how many containers are not running properly", async () => {
    vi.mocked(listUnhealthyContainers).mockResolvedValue([
      container(),
      container({ hostId: "h2", hostname: "coder", name: "docker-backend-1",
        status: "Restarting (1) 50 seconds ago", composeDir: "/opt/docker" }),
    ]);
    renderBanner();
    await waitFor(() =>
      expect(screen.getByText("2 containers are not running properly")).toBeInTheDocument());
  });

  it("names the container, the host and what is wrong with it", async () => {
    vi.mocked(listUnhealthyContainers).mockResolvedValue([container()]);
    renderBanner();
    await waitFor(() =>
      expect(screen.getByText("1 container is not running properly")).toBeInTheDocument());

    // Collapsed by default: the count is the alarm, the detail is on request.
    expect(screen.queryByText("wikipedia")).not.toBeInTheDocument();
    fireEvent.click(screen.getByText("Show"));

    expect(screen.getByText("wikipedia")).toBeInTheDocument();
    expect(screen.getByText("ai")).toBeInTheDocument();
    expect(screen.getByText(/restarting in a loop/)).toBeInTheDocument();
    // Docker's own line, which carries how long and what it exited with.
    expect(screen.getByText("Restarting (0) 40 seconds ago")).toBeInTheDocument();
    // And where it lives, so acting on it does not start with a search.
    expect(screen.getByText("/home/keith/test2")).toBeInTheDocument();
  });

  it("shows nothing at all when the fleet is healthy", async () => {
    vi.mocked(listUnhealthyContainers).mockResolvedValue([]);
    const { container: root } = renderBanner();
    await waitFor(() => expect(listUnhealthyContainers).toHaveBeenCalled());
    // A permanent "0 problems" band trains people to stop reading the top of the
    // page, which is where the next real one will appear.
    expect(root).toBeEmptyDOMElement();
  });

  it("says when the evidence is old", async () => {
    // A crash loop read from a three-day-old inventory is not news. A banner that
    // does not say so sends somebody to fix a container that has been fine since
    // Tuesday.
    const threeDaysAgo = new Date(Date.now() - 3 * 86_400_000).toISOString();
    vi.mocked(listUnhealthyContainers).mockResolvedValue([
      container({ collectedAt: threeDaysAgo }),
    ]);
    renderBanner();
    await waitFor(() =>
      expect(screen.getByText(/oldest reading is 3 days old/)).toBeInTheDocument());
  });
});
