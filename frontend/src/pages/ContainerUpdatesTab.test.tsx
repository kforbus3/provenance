import "@testing-library/jest-dom/vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ContainerUpdatesTab } from "./ContainerUpdatesTab";
import { useAuthStore } from "../store/auth";

// The white screen.
//
// The server sends `hosts: null` (not `[]`) for an image no host runs any more,
// because Go marshals a nil slice as null. One `.filter` on that threw, React
// unmounted the whole app, and /stacks was a blank page.
//
// It was not an edge case: upgrading this product replaces its own containers,
// so the tags it just superseded keep their rows until the next check pass
// prunes them. Every upgrade produced several, and the page broke right after
// every upgrade — the exact moment somebody goes to look at it.

vi.mock("../api/containerUpdates", () => ({
  listContainerUpdates: vi.fn(),
  checkContainerUpdates: vi.fn(),
}));

import { listContainerUpdates } from "../api/containerUpdates";

// The tab now defaults to showing only the images something is available for.
// Every test in this file is about RENDERING -- null hosts, a row for an image no
// host runs any more, the image filter not matching hostnames -- on fixtures whose
// verdicts that default hides. So these render the full list, which is what their
// subject requires; the default itself is covered in
// ContainerUpdatesTab.filter.test.tsx.
function showEverything() {
  fireEvent.click(screen.getByRole("checkbox"));
}

function renderTab() {
  useAuthStore.setState({
    user: { id: "1", username: "alice" },
    permissions: ["Host.Scan", "Command.Run"],
    // Super admin short-circuits has(), so the assertions below are about the
    // component's own logic rather than the permission plumbing.
    isSuperAdmin: true, loaded: true, restore: vi.fn(),
  } as never);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><ContainerUpdatesTab /></QueryClientProvider>,
  );
}

describe("ContainerUpdatesTab", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders an image whose hosts are null instead of blanking the page", async () => {
    vi.mocked(listContainerUpdates).mockResolvedValue([
      {
        repository: "provenance-backend",
        tag: "1.2.3",
        checkedAt: new Date().toISOString(),
        hosts: null, // what the server actually sends after an upgrade
      },
    ] as never);

    renderTab();
    showEverything();

    await waitFor(() =>
      expect(screen.getByText(/provenance-backend:1\.2\.3/)).toBeInTheDocument(),
    );
  });

  it("still renders when a normal row and a null-hosts row are mixed", async () => {
    vi.mocked(listContainerUpdates).mockResolvedValue([
      {
        repository: "provenance-backend", tag: "1.2.3",
        checkedAt: new Date().toISOString(), hosts: null,
      },
      {
        repository: "nginx", tag: "1.24", latestTag: "1.27",
        checkedAt: new Date().toISOString(),
        hosts: [{ hostId: "h1", hostname: "web1", stale: true }],
      },
    ] as never);

    renderTab();
    showEverything();

    await waitFor(() => expect(screen.getByText(/nginx:1\.24/)).toBeInTheDocument());
    expect(screen.getByText(/provenance-backend:1\.2\.3/)).toBeInTheDocument();
    // The actionable one sorts first and is offered a rollout; the null-hosts one
    // must not be, because there is nothing to roll out to.
    expect(screen.getAllByText("Roll out")).toHaveLength(1);
    // And the leftover row says what it is, rather than "up to date" — a claim
    // about something you are running.
    expect(screen.getByText("no longer running")).toBeInTheDocument();
  });
});

describe("ContainerUpdatesTab filtering", () => {
  beforeEach(() => vi.clearAllMocks());

  const rows = [
    {
      repository: "provenance-dockerproxy", tag: "latest",
      checkedAt: new Date().toISOString(),
      hosts: [{ hostId: "h1", hostname: "control01", stale: false }],
    },
    {
      repository: "nginx", tag: "1.24", latestTag: "1.27",
      checkedAt: new Date().toISOString(),
      hosts: [{ hostId: "h2", hostname: "docker", stale: true }],
    },
  ];

  it("does not match a hostname against image names", async () => {
    // Typing "docker" matched BOTH the host called docker and the image
    // provenance-dockerproxy running on control01 — which is not what anyone types
    // a hostname to find. The text box searches images; the host picker is exact.
    vi.mocked(listContainerUpdates).mockResolvedValue(rows as never);
    renderTab();
    showEverything();
    await waitFor(() => expect(screen.getByText(/nginx:1\.24/)).toBeInTheDocument());

    const imageFilter = screen.getByPlaceholderText("Filter by image");
    fireEvent.change(imageFilter, { target: { value: "docker" } });

    // The image whose NAME contains "docker" is a legitimate match.
    await waitFor(() =>
      expect(screen.getByText(/provenance-dockerproxy/)).toBeInTheDocument());
    // The image merely RUNNING on the host called docker is not.
    expect(screen.queryByText(/nginx:1\.24/)).not.toBeInTheDocument();
  });

  it("offers every host reporting containers, and filters to one exactly", async () => {
    vi.mocked(listContainerUpdates).mockResolvedValue(rows as never);
    renderTab();
    await waitFor(() => expect(screen.getByText(/nginx:1\.24/)).toBeInTheDocument());

    const host = screen.getByLabelText("Host");
    fireEvent.mouseDown(host);
    fireEvent.change(host, { target: { value: "docker" } });

    const option = await screen.findByText("docker", { selector: "li,li *" });
    fireEvent.click(option);

    await waitFor(() =>
      expect(screen.queryByText(/provenance-dockerproxy/)).not.toBeInTheDocument());
    expect(screen.getByText(/nginx:1\.24/)).toBeInTheDocument();
  });

  it("says a filter is hiding things rather than looking empty", async () => {
    // An empty table with a filter set reads as an empty fleet, which is the
    // same "silence looks like an answer" failure as everywhere else here.
    vi.mocked(listContainerUpdates).mockResolvedValue(rows as never);
    renderTab();
    await waitFor(() => expect(screen.getByText(/nginx:1\.24/)).toBeInTheDocument());

    fireEvent.change(screen.getByPlaceholderText("Filter by image"),
      { target: { value: "nothing-matches-this" } });

    await waitFor(() =>
      expect(screen.getByText(/2 images in total/)).toBeInTheDocument());
  });
});

describe("ContainerUpdatesTab unchecked images", () => {
  beforeEach(() => vi.clearAllMocks());

  it("shows an image that is running but has never been checked", async () => {
    // Twenty-four containers appeared on a host and the page showed none of
    // them, because rows came from the CHECKED table and the check runs every
    // twelve hours. "We have not asked yet" is not "there is nothing there".
    vi.mocked(listContainerUpdates).mockResolvedValue([
      {
        repository: "jellyfin/jellyfin", tag: "10.11.11",
        checkedAt: "", // never asked
        hosts: [{ hostId: "h1", hostname: "docker", stale: false }],
      },
    ] as never);

    renderTab();

    await waitFor(() =>
      expect(screen.getByText(/jellyfin\/jellyfin:10\.11\.11/)).toBeInTheDocument());
    expect(screen.getByText("not checked yet")).toBeInTheDocument();
    // And must not read as up to date, which is a claim nobody has verified.
    expect(screen.queryByText("up to date")).not.toBeInTheDocument();
  });
});

describe("ContainerUpdatesTab summary", () => {
  beforeEach(() => vi.clearAllMocks());

  it("counts newer versions and rebuilds separately", async () => {
    // "8 images have something newer available" over a list where seven rows read
    // "rebuilt" and one reads a version number invites exactly one question: why
    // does only one show an update? Both are actionable and only one is a new
    // version, which is the distinction the rest of the screen is built on.
    const rows = [
      {
        repository: "nginx", tag: "1.24", latestTag: "1.27",
        checkedAt: new Date().toISOString(),
        hosts: [{ hostId: "h1", hostname: "web1", stale: false }],
      },
      ...["redis", "caddy"].map((r) => ({
        repository: r, tag: "1", digest: "sha256:new",
        note: "tag moved: rebuilt at the same version",
        checkedAt: new Date().toISOString(),
        hosts: [{ hostId: "h2", hostname: "docker", stale: true }],
      })),
    ];
    vi.mocked(listContainerUpdates).mockResolvedValue(rows as never);
    renderTab();

    await waitFor(() =>
      expect(screen.getByText(/1 image has a newer version/)).toBeInTheDocument());
    expect(screen.getByText(/2 have been rebuilt at the same version/)).toBeInTheDocument();
    // And it explains why the list can look shorter than the total.
    expect(screen.getByText(/same version republished/)).toBeInTheDocument();
  });
});
