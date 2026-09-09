import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { HostDetailsDialog } from "./HostsPage";
import * as hostsApi from "../api/hosts";
import * as imagingApi from "../api/imaging";
import { useAuthStore } from "../store/auth";

// Rollouts select from the machine table, so an enrolled host with no machine
// record cannot be reached by one — not even by a rollout aimed at the whole
// fleet. There was no way to create that record for a host this deployment did
// not image, and no indication anywhere that the record was what was missing:
// the host looked healthy, the rollout simply never mentioned it.
//
// So the host's own details page has to say so, and offer the fix.

vi.mock("../api/hosts", async () => {
  const actual = await vi.importActual<typeof hostsApi>("../api/hosts");
  return { ...actual, getHost: vi.fn(), listHostSoftware: vi.fn(), refreshHostFacts: vi.fn(),
           clearHostKeyPins: vi.fn() };
});
vi.mock("../api/imaging", async () => {
  const actual = await vi.importActual<typeof imagingApi>("../api/imaging");
  return { ...actual, listMachines: vi.fn(), registerHostForUpdates: vi.fn() };
});

function host() {
  return {
    id: "h1", hostname: "kiosk-04", description: "", environment: "lab", owner: "ops",
    sshPort: 22, sshUser: "fleet", tags: [], authMethod: "fleet_cert", protocol: "ssh",
    rdpPort: 3389, enrolled: true, createdAt: "", updatedAt: "", address: "10.0.4.21",
    status: { status: "online", sshOk: true, wgOk: true, lastError: "" },
  } as unknown as hostsApi.Host;
}

function machines(list: Partial<imagingApi.Machine>[]) {
  return { machines: list as imagingApi.Machine[], counts: {}, versions: {}, interval: 300 };
}

function renderDetails(h: hostsApi.Host = host()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <HostDetailsDialog host={h} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

describe("registering an enrolled host for A/B updates", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useAuthStore.setState({
      user: { id: "1", username: "alice" }, permissions: ["Imaging.Manage"],
      isSuperAdmin: false, loaded: true, restore: vi.fn(),
    } as never);
    vi.mocked(hostsApi.getHost).mockResolvedValue(host());
    vi.mocked(hostsApi.listHostSoftware).mockResolvedValue([]);
    vi.mocked(imagingApi.listMachines).mockResolvedValue(machines([]));
  });

  it("says why a rollout cannot reach a host that has no machine record", async () => {
    renderDetails();
    // The point is not the button — it is that the host says what is wrong.
    // Someone looking at a healthy host wondering why a rollout skipped it
    // should find the answer here rather than infer it.
    expect(await screen.findByText(/rollouts cannot reach it/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /register for updates/i })).toBeInTheDocument();
  });

  it("registers the host and then reports what the machine said", async () => {
    vi.mocked(imagingApi.registerHostForUpdates).mockResolvedValue(
      { id: "7c:1e:52:aa:bb:cc", hostId: "h1", slot: "B", version: "2026.09.1" } as imagingApi.Machine,
    );
    renderDetails();
    fireEvent.click(await screen.findByRole("button", { name: /register for updates/i }));
    await waitFor(() =>
      expect(imagingApi.registerHostForUpdates).toHaveBeenCalledWith("h1"));
  });

  it("shows the real slot and version once a record exists, not the offer", async () => {
    vi.mocked(imagingApi.listMachines).mockResolvedValue(machines([
      { id: "7c:1e:52:aa:bb:cc", hostId: "h1", slot: "B", version: "2026.09.1" },
    ]));
    renderDetails();
    expect(await screen.findByText(/2026\.09\.1/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /register for updates/i })).toBeNull();
  });

  // A machine record belonging to a different host must not make this one look
  // registered — that would hide the offer on exactly the host that needs it.
  it("does not treat another host's machine record as this host's", async () => {
    vi.mocked(imagingApi.listMachines).mockResolvedValue(machines([
      { id: "aa:bb:cc:dd:ee:ff", hostId: "h2", slot: "A", version: "2026.08.9" },
    ]));
    renderDetails();
    expect(await screen.findByRole("button", { name: /register for updates/i })).toBeInTheDocument();
  });

  // The server refuses a host that has no ab-update. That refusal is the most
  // useful thing this feature says — it tells someone their machine is not what
  // they thought — so it has to reach the screen rather than vanish.
  it("surfaces the server's refusal instead of failing silently", async () => {
    vi.mocked(imagingApi.registerHostForUpdates).mockRejectedValue({
      response: { data: { error: "kiosk-04 has no /usr/local/sbin/ab-update, so it is not an A/B machine" } },
    });
    renderDetails();
    fireEvent.click(await screen.findByRole("button", { name: /register for updates/i }));
    expect(await screen.findByText(/not an A\/B machine/i)).toBeInTheDocument();
  });

  it("shows nothing to someone without imaging permission", async () => {
    useAuthStore.setState({ permissions: [], isSuperAdmin: false } as never);
    renderDetails();
    await screen.findByText(/kiosk-04/);
    expect(screen.queryByRole("button", { name: /register for updates/i })).toBeNull();
    // And it must not have asked for the machine list it may not read.
    expect(imagingApi.listMachines).not.toHaveBeenCalled();
  });
});
