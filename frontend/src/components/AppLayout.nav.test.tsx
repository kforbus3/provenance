import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { AppLayout } from "./AppLayout";
import { useAuthStore } from "../store/auth";
import { useUIStore } from "../store/ui";

// The sidebar was thirty-five items in one flat list, ordered by when each was
// built. Grouping them is only an improvement if the groups behave: a section
// must not appear when the user can open nothing inside it, and the section
// holding the current page must be open when the page loads.

vi.mock("../api/assistant", () => ({
  listAssistantApprovals: vi.fn().mockResolvedValue([]),
  assistantStatus: vi.fn(),
}));

import { assistantStatus } from "../api/assistant";

function renderNav(permissions: string[], path = "/") {
  useAuthStore.setState({
    user: { id: "1", username: "alice" }, permissions,
    isSuperAdmin: false, loaded: true, restore: vi.fn(),
  } as never);
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route element={<AppLayout />}>
            <Route path="*" element={<div>page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("sidebar sections", () => {
  beforeEach(() => {
    useUIStore.setState({ navCollapsed: [], sidebarOpen: true } as never);
  });

  it("groups items under headings instead of one flat list", () => {
    renderNav(["Host.View", "Host.Connect", "Audit.View"]);
    expect(screen.getByText("Access")).toBeInTheDocument();
    expect(screen.getByText("Compliance")).toBeInTheDocument();
    expect(screen.getByText("Hosts")).toBeInTheDocument();
  });

  // The failure this prevents: a heading with nothing under it tells a user
  // only that a capability exists which they are not allowed to have.
  it("hides a section whose every item the user lacks permission for", () => {
    renderNav(["Host.View"]);
    expect(screen.getByText("Access")).toBeInTheDocument();
    expect(screen.queryByText("Compliance")).toBeNull();
    expect(screen.queryByText("Identity & Policy")).toBeNull();
  });

  // Deep links and reloads land inside a section. Finding the menu shut around
  // the page you are on is disorienting, and it would happen every time.
  it("opens the section containing the current page even when collapsed", () => {
    useUIStore.setState({ navCollapsed: ["Compliance"] } as never);
    renderNav(["Audit.View"], "/audit");
    expect(screen.getByText("Audit")).toBeVisible();
  });

  it("remembers a section the user collapsed", () => {
    renderNav(["Host.View", "Host.Connect"]);
    expect(screen.getByText("Terminals")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Access"));
    expect(useUIStore.getState().navCollapsed).toContain("Access");
  });

  // Dashboard and Ask are entry points, not destinations inside a category;
  // burying them under a heading would be worse than the flat list was.
  it("keeps the top-level entry points out of the sections", () => {
    renderNav([]);
    expect(screen.getByText("Dashboard")).toBeInTheDocument();
  });

  // "/" is a prefix of every path, so only an exact match may select it —
  // otherwise Dashboard highlights on every page in the product.
  it("does not mark Dashboard active on another page", () => {
    renderNav(["Host.View"], "/hosts");
    const dash = screen.getByText("Dashboard").closest("a");
    expect(dash).not.toHaveClass("Mui-selected");
  });
});

// The sidebar/route cross-checks -- every entry resolves to a route in App.tsx,
// and claims the permission that route enforces -- live in
// deploy/builder-runner/test_nav_routes.py instead of here.
//
// They have to read App.tsx, and this project's tsconfig has no node types: a
// `node:fs` import passes vitest and then fails `tsc -b` in the production
// image build, which is how it got caught. Reading files is what the Python
// checks already do, so that is where a check that reads a file belongs.

// Ask is a link to a page that cannot do anything until somebody points the assistant
// at a model server. `Assistant.Use` is granted by default and the setting defaults to
// off, so on a fresh install every operator saw a sidebar entry whose whole content was
// an explanation that an administrator had not set it up.
describe("the Ask item follows the assistant's configuration", () => {
  beforeEach(() => {
    useUIStore.setState({ navCollapsed: [], sidebarOpen: true } as never);
    vi.clearAllMocks();
  });

  it("is hidden when the assistant is not configured", async () => {
    (assistantStatus as ReturnType<typeof vi.fn>).mockResolvedValue({ enabled: false });
    renderNav(["Assistant.Use"]);
    await waitFor(() => expect(assistantStatus).toHaveBeenCalled());
    expect(screen.queryByRole("link", { name: /Ask/ })).not.toBeInTheDocument();
  });

  it("appears once it is configured", async () => {
    (assistantStatus as ReturnType<typeof vi.fn>).mockResolvedValue({ enabled: true });
    renderNav(["Assistant.Use"]);
    await waitFor(() => expect(screen.getByRole("link", { name: /Ask/ })).toBeInTheDocument());
  });

  // An unreachable or failing status endpoint must not advertise the feature: not
  // knowing whether it exists is not a reason to link to it.
  it("stays hidden when the status cannot be read", async () => {
    (assistantStatus as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("nope"));
    renderNav(["Assistant.Use"]);
    await waitFor(() => expect(assistantStatus).toHaveBeenCalled());
    expect(screen.queryByRole("link", { name: /Ask/ })).not.toBeInTheDocument();
  });

  // And it is never shown to somebody who could not open it anyway.
  it("is hidden without the permission even when configured", async () => {
    (assistantStatus as ReturnType<typeof vi.fn>).mockResolvedValue({ enabled: true });
    renderNav(["Host.View"]);
    expect(screen.queryByRole("link", { name: /Ask/ })).not.toBeInTheDocument();
  });
});
