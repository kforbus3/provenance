import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { HostDetailsDialog } from "./HostsPage";
import * as hostsApi from "../api/hosts";

// An offline host used to show the word "offline" and nothing else, while the
// monitor's recorded reason sat unread in the API — which is how a rebuilt host's
// changed SSH key looked like a broken WireGuard tunnel. The reason must be
// visible, and the one cause with a specific remedy must offer it.

vi.mock("../api/hosts", async () => {
  const actual = await vi.importActual<typeof hostsApi>("../api/hosts");
  return {
    ...actual,
    getHost: vi.fn(),
    listHostSoftware: vi.fn(),
    refreshHostFacts: vi.fn(),
    clearHostKeyPins: vi.fn(),
  };
});

const PIN_ERROR =
  "ssh handshake with debian-ab-test:22: ssh: handshake failed: host key for debian-ab-test " +
  "does not match the pinned key (possible MITM, or the host was rebuilt — remove its pin to re-trust)";

function host(lastError: string, status = "offline") {
  return {
    id: "h1", hostname: "debian-ab-test", description: "", environment: "lab", owner: "ops",
    sshPort: 22, sshUser: "fleet", tags: [], authMethod: "fleet_cert", protocol: "ssh",
    rdpPort: 3389, enrolled: true, createdAt: "", updatedAt: "", wgAddress: "10.100.0.26",
    status: { status, sshOk: false, wgOk: false, lastError },
  } as unknown as hostsApi.Host;
}

function renderDetails(h: hostsApi.Host) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <HostDetailsDialog host={h} onClose={() => {}} />
    </QueryClientProvider>,
  );
}

describe("HostDetailsDialog offline reason", () => {
  beforeEach(() => {
    vi.mocked(hostsApi.getHost).mockImplementation(async () => host(PIN_ERROR));
    vi.mocked(hostsApi.listHostSoftware).mockResolvedValue([]);
    vi.mocked(hostsApi.clearHostKeyPins).mockResolvedValue(2);
  });

  it("shows the recorded reason a host is offline", async () => {
    renderDetails(host("dial tcp 10.100.0.26:22: i/o timeout"));
    expect(await screen.findByText(/i\/o timeout/)).toBeInTheDocument();
  });

  it("offers to re-trust a rebuilt host's key and clears every pin", async () => {
    vi.mocked(hostsApi.getHost).mockResolvedValue(host(PIN_ERROR));
    renderDetails(host(PIN_ERROR));

    expect(await screen.findByText(/does not match the pinned key/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Trust new key/ }));

    await waitFor(() => expect(hostsApi.clearHostKeyPins).toHaveBeenCalledWith("h1"));
    // The count matters: a host is pinned per dialed address, so clearing one
    // identity and reporting success would leave the host still refused.
    expect(await screen.findByText(/Cleared 2 pins/)).toBeInTheDocument();
  });

  it("does not offer the re-trust shortcut for unrelated failures", async () => {
    const h = host("dial tcp 10.100.0.26:22: connect: connection refused");
    vi.mocked(hostsApi.getHost).mockResolvedValue(h);
    renderDetails(h);

    expect(await screen.findByText(/connection refused/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Trust new key/ })).not.toBeInTheDocument();
  });

  it("stays quiet about a stale error once the host is back online", async () => {
    const h = host(PIN_ERROR, "online");
    vi.mocked(hostsApi.getHost).mockResolvedValue(h);
    renderDetails(h);

    await waitFor(() => expect(hostsApi.getHost).toHaveBeenCalled());
    expect(screen.queryByText(/does not match the pinned key/)).not.toBeInTheDocument();
  });
});
