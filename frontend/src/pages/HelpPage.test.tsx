import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { describe, it, expect } from "vitest";
import { HelpPage } from "./HelpPage";

function renderHelp(path = "/help") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/help" element={<HelpPage />} />
        <Route path="/help/:slug" element={<HelpPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("HelpPage", () => {
  it("renders the sidebar of guides and the default doc content", () => {
    renderHelp();
    // Sidebar lists the guides (also cross-linked from content, hence getAllByText).
    expect(screen.getAllByText("API Reference").length).toBeGreaterThan(0);
    expect(screen.getAllByText("User Guide").length).toBeGreaterThan(0);
    // The default (first) doc is the Installation guide; its H1 renders as content.
    expect(screen.getAllByText(/Installation/i).length).toBeGreaterThan(0);
  });

  it("renders a specific guide from the route slug with anchored headings", async () => {
    const { container } = renderHelp("/help/security-guide");
    // Content for that slug renders.
    await screen.findAllByText(/threat model/i);
    // Markdown headings get ids from slugify(), enabling deep links.
    expect(container.querySelector("h2[id], h3[id]")).not.toBeNull();
  });

  it("searches across doc sections and shows ranked results", async () => {
    renderHelp();
    fireEvent.change(screen.getByPlaceholderText("Search help…"), {
      target: { value: "recovery codes" },
    });
    // "recovery codes" appears in multiple guides; result headings render its text.
    // (The sidebar has no "recovery" text, so any match comes from search results.)
    const hits = await screen.findAllByText(/recovery/i);
    expect(hits.length).toBeGreaterThan(0);
  });
});
