import "@testing-library/jest-dom/vitest";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import BlastRadiusWarning from "./BlastRadiusWarning";
import * as hostsApi from "../api/hosts";

function renderWith(hostIds: string[]) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <BlastRadiusWarning hostIds={hostIds} />
    </QueryClientProvider>,
  );
}

beforeEach(() => vi.restoreAllMocks());

describe("the preview speaks only when it has something to say", () => {
  it("renders nothing when no host in the selection carries another", async () => {
    vi.spyOn(hostsApi, "hostBlastRadius").mockResolvedValue({ hosts: 2, findings: [] });
    const { container } = renderWith(["a", "b"]);
    await waitFor(() => expect(hostsApi.hostBlastRadius).toHaveBeenCalled());
    // An always-present panel trains people to scroll past it, and the one time
    // it matters it looks like every time it did not.
    expect(container).toBeEmptyDOMElement();
  });

  it("does not claim safety when the check itself failed", async () => {
    vi.spyOn(hostsApi, "hostBlastRadius").mockRejectedValue(new Error("boom"));
    renderWith(["a"]);
    // "We could not look" and "there is nothing there" are different answers.
    expect(await screen.findByText(/not a statement that nothing does/i)).toBeInTheDocument();
  });
});

describe("severity reflects whether unselected hosts are affected", () => {
  it("leads with the unselected hosts when there are any", async () => {
    vi.spyOn(hostsApi, "hostBlastRadius").mockResolvedValue({
      hosts: 2,
      findings: [{
        severity: "critical", kind: "storage", hostId: "nas", hostname: "nas",
        dependents: ["guest-a", "guest-b", "guest-c"], inSelection: 1, outside: 2,
        message: "nas is in this action, and 3 hosts have their disks served by it. "
          + "2 of them are not in this selection.",
      }],
    });
    renderWith(["nas", "guest-a"]);
    expect(await screen.findByText(/reaches hosts you have not selected/i)).toBeInTheDocument();
    expect(screen.getByText(/2 of them are not in this selection/i)).toBeInTheDocument();
    expect(screen.getByText("guest-c")).toBeInTheDocument();
  });

  it("frames an all-inside selection as an ordering problem, not collateral", async () => {
    vi.spyOn(hostsApi, "hostBlastRadius").mockResolvedValue({
      hosts: 3,
      findings: [{
        severity: "warning", kind: "hypervisor", hostId: "hypervisor", hostname: "hypervisor",
        dependents: ["guest-a", "guest-b"], inSelection: 2, outside: 0,
        message: "hypervisor is in this action, and 2 hosts run on it as guests — all of them "
          + "also in this selection, so the order this runs in decides whether they survive it.",
      }],
    });
    renderWith(["hypervisor", "guest-a", "guest-b"]);
    expect(await screen.findByText(/order matters here/i)).toBeInTheDocument();
    expect(screen.queryByText(/reaches hosts you have not selected/i)).not.toBeInTheDocument();
  });
});
