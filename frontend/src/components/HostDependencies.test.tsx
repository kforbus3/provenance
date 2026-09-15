import "@testing-library/jest-dom/vitest";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import HostDependencies from "./HostDependencies";
import * as hostsApi from "../api/hosts";

function renderWith() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <HostDependencies hostId="h1" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(hostsApi, "listHosts").mockResolvedValue({
    hosts: [
      { id: "h1", hostname: "guest-a" },
      { id: "h2", hostname: "nas" },
    ] as never,
    count: 2,
  });
});

describe("recording what a host stands on", () => {
  it("says plainly that nothing is recorded, and why that matters", async () => {
    vi.spyOn(hostsApi, "listHostDependencies").mockResolvedValue({ dependsOn: [], dependents: [] });
    renderWith();
    // An empty state that just said "none" would read as a fact about the fleet
    // rather than a gap in what has been told to it.
    expect(await screen.findByText(/no bulk action can warn about it/i)).toBeInTheDocument();
  });

  it("shows both directions, because they answer different questions", async () => {
    vi.spyOn(hostsApi, "listHostDependencies").mockResolvedValue({
      dependsOn: [{
        hostId: "h1", hostname: "guest-a", dependsOnId: "h2", dependsOn: "nas",
        kind: "storage", note: "NFS over 10G",
      }],
      dependents: [{
        hostId: "h3", hostname: "guest-b", dependsOnId: "h1", dependsOn: "guest-a",
        kind: "other", note: "",
      }],
    });
    renderWith();
    expect(await screen.findByText("nas")).toBeInTheDocument();
    expect(screen.getByText("NFS over 10G")).toBeInTheDocument();
    expect(screen.getByText(/guest-b \(other\)/)).toBeInTheDocument();
  });

  it("surfaces the cycle path the server refused, not a generic failure", async () => {
    vi.spyOn(hostsApi, "listHostDependencies").mockResolvedValue({ dependsOn: [], dependents: [] });
    vi.spyOn(hostsApi, "addHostDependency").mockRejectedValue({
      response: { data: { error: "that would make a loop: nas → hypervisor → guest-a → nas" } },
    });
    renderWith();
    await screen.findByText(/no bulk action can warn about it/i);

    // Drive the Autocomplete the way the project's other tests drive MUI:
    // fireEvent only, since user-event is not a dependency here.
    const picker = screen.getByLabelText("Stands on");
    fireEvent.mouseDown(picker);
    fireEvent.change(picker, { target: { value: "nas" } });
    fireEvent.click(await screen.findByText("nas"));
    fireEvent.click(screen.getByRole("button", { name: /^add$/i }));

    // Finding the loop by hand means walking a graph the operator cannot see.
    await waitFor(() =>
      expect(screen.getByText(/nas → hypervisor → guest-a → nas/)).toBeInTheDocument());
  });
});
