import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";

// keith clicked the package count on the Images tab and got
//   error  "missing access token"
// The count was an <a href> straight at /api/v1/imaging/images/<n>/sbom, and a
// browser navigation carries no Authorization header — Provenance's session
// cookies are scoped to /api/v1/auth, so nothing authenticated the request.

vi.mock("../api/imaging", async () => {
  const actual = await vi.importActual<typeof import("../api/imaging")>("../api/imaging");
  return {
    ...actual,
    imageSbomPackages: vi.fn(),
    downloadImageSbom: vi.fn(),
    imageDownloadUrl: (n: string) => `/api/v1/imaging/images/${n}/download?token=tok`,
    startImageDownload: vi.fn(),
  };
});
import * as api from "../api/imaging";
import type { Image } from "../api/imaging";
import { ImagesTabForTest as ImagesTab } from "./ImagingPage";

const IMAGE: Image = {
  name: "debian-trixie-amd64-ab.img.zst", distro: "debian", suite: "trixie", arch: "amd64",
  size: 2_100_000_000, created: "2026-09-15T22:04:00Z", hasSbom: true, packages: 262,
  encrypted: false, secureBoot: false,
};

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ImagesTab images={[IMAGE]} dir="/out" imagerArches={{}} canBuild
                 onChanged={() => {}} setMsg={() => {}} />
    </QueryClientProvider>,
  );
}

describe("Images tab — package count", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(api.imageSbomPackages).mockResolvedValue([
      { name: "openssl", version: "3.5.1" },
      { name: "adduser", version: "3.152" },
    ]);
  });

  // The count must not be a link to the API at all: that is the bug.
  it("does not navigate to the API endpoint", () => {
    renderTab();
    const btn = screen.getByRole("button", { name: /262 packages/ });
    expect(btn).not.toHaveAttribute("href");
  });

  it("lists the packages, fetched with the API client", async () => {
    renderTab();
    fireEvent.click(screen.getByRole("button", { name: /262 packages/ }));

    await waitFor(() => expect(api.imageSbomPackages).toHaveBeenCalledWith(IMAGE.name));
    expect(await screen.findByText("openssl")).toBeInTheDocument();
    expect(screen.getByText("3.5.1")).toBeInTheDocument();
  });

  // 262 is a number; "openssl 3.5.1" is an answer. Filtering is what makes the
  // list usable on an image with hundreds of packages.
  it("filters the list", async () => {
    renderTab();
    fireEvent.click(screen.getByRole("button", { name: /262 packages/ }));
    await screen.findByText("openssl");

    fireEvent.change(screen.getByLabelText("Filter"), { target: { value: "openss" } });

    expect(screen.getByText("openssl")).toBeInTheDocument();
    expect(screen.queryByText("adduser")).not.toBeInTheDocument();
  });
});

// The Download button answered an error twice: first because it was a link straight at
// the API (a navigation carries no Authorization header), then because the route was
// still behind the header check despite a comment saying otherwise. What is testable
// from here is the third way it can break: an href is built when the row renders, and
// the token in it expires in fifteen minutes, so a tab left open holds a dead link.
describe("Images tab — download", () => {
  it("is an action taken on click, not a link built at render time", async () => {
    renderTab();
    const btn = await screen.findByRole("button", { name: "Download" });
    // No href: the URL must be built from the token that is current when the
    // operator clicks, not the one that was current when the table was drawn.
    expect(btn).not.toHaveAttribute("href");

    fireEvent.click(btn);
    expect(api.startImageDownload).toHaveBeenCalledWith(IMAGE.name);
  });
});
