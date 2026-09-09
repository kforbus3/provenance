import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { AppLayout, NAV_TOP, NAV_SECTIONS, NAV_BOTTOM } from "./AppLayout";
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

// Every sidebar entry must lead somewhere, and lead somewhere with the same
// permission it claims. Both halves drift silently: a route renamed in App.tsx
// leaves a menu item that navigates to the catch-all redirect and dumps the
// user on the dashboard with no error, and a permission changed on the route
// but not the item leaves an entry that is visible and then refuses to open.
describe("the sidebar agrees with the route table", () => {
  const app = readFileSync(join(__dirname, "..", "App.tsx"), "utf8");
  const all = [...NAV_TOP, ...NAV_SECTIONS.flatMap((s) => s.items), ...NAV_BOTTOM];

  it("covers every item with a real route", () => {
    const missing = all
      .map((i) => i.to.replace(/^\//, ""))
      .filter((path) => path !== "")
      .filter((path) => !new RegExp(`path="${path}"`).test(app));
    expect(missing, `sidebar entries with no route in App.tsx: ${missing.join(", ")}`)
      .toEqual([]);
  });

  it("claims the same permission the route enforces", () => {
    const wrong: string[] = [];
    for (const item of all) {
      const path = item.to.replace(/^\//, "");
      if (!path) continue;
      const m = app.match(new RegExp(`path="${path}"[^\\n]*`));
      if (!m) continue;
      const routePerm = m[0].match(/permission="([^"]+)"/)?.[1];
      if ((routePerm ?? undefined) !== item.perm) {
        wrong.push(`${item.to}: sidebar=${item.perm ?? "none"} route=${routePerm ?? "none"}`);
      }
    }
    expect(wrong, `sidebar/route permission mismatch: ${wrong.join("; ")}`).toEqual([]);
  });

  it("has no duplicate destinations", () => {
    const seen = all.map((i) => i.to);
    expect(seen.length).toBe(new Set(seen).size);
  });
});
