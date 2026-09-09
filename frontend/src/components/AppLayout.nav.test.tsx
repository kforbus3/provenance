import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
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

vi.mock("../api/assistant", () => ({ listAssistantApprovals: vi.fn().mockResolvedValue([]) }));

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
