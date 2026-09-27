import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { HostDetailsDialog } from "./HostsPage";
import * as hostsApi from "../api/hosts";
import { useAuthStore } from "../store/auth";

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
    listHostKeyPins: vi.fn(),
  };
});

const PIN_ERROR =
  "ssh handshake with debian-ab-test:22: ssh: handshake failed: host key for debian-ab-test " +
  "does not match the pinned key (possible MITM, or the host was rebuilt — remove its pin to re-trust)";

const OLD_PIN: hostsApi.HostKeyPin = {
  host: "debian-ab-test", keyType: "ssh-rsa", source: "tofu",
  fingerprint: "SHA256:oldkeyoldkeyoldkeyoldkeyoldkeyoldkeyoldke",
};

function host(lastError: string, status = "offline") {
  return {
    id: "h1", hostname: "debian-ab-test", description: "", environment: "lab", owner: "ops",
    sshPort: 22, sshUser: "fleet", tags: [], authMethod: "prov_cert", protocol: "ssh",
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
    vi.mocked(hostsApi.listHostKeyPins).mockResolvedValue([OLD_PIN]);
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

// A host whose health check does not use SSH — a switch probed another way —
// stays "online" while every terminal session is refused on the old pin. The
// remedy used to live only in the offline alert, so there was nowhere to click.
describe("HostDetailsDialog SSH host key section", () => {
  beforeEach(() => {
    vi.mocked(hostsApi.listHostSoftware).mockResolvedValue([]);
    vi.mocked(hostsApi.clearHostKeyPins).mockReset().mockResolvedValue(1);
    vi.mocked(hostsApi.listHostKeyPins).mockResolvedValue([OLD_PIN]);
    useAuthStore.setState({ permissions: ["Host.View", "Host.Enroll"], isSuperAdmin: false });
  });

  it("lets an operator re-trust an ONLINE host's key, after confirming", async () => {
    const h = host("", "online");
    vi.mocked(hostsApi.getHost).mockResolvedValue(h);
    renderDetails(h);

    expect(await screen.findByText(/SHA256:oldkeyoldkey/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Trust new key/ }));
    // One click only opens the confirmation; nothing is cleared yet.
    expect(await screen.findByText(/Confirm it is really your host first/)).toBeInTheDocument();
    expect(hostsApi.clearHostKeyPins).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /^Trust new key$/ }));
    await waitFor(() => expect(hostsApi.clearHostKeyPins).toHaveBeenCalledWith("h1"));
    expect(await screen.findByText(/Cleared 1 pin —/)).toBeInTheDocument();
  });

  it("shows the pinned key but no remedy without Host.Enroll", async () => {
    useAuthStore.setState({ permissions: ["Host.View"], isSuperAdmin: false });
    const h = host("", "online");
    vi.mocked(hostsApi.getHost).mockResolvedValue(h);
    renderDetails(h);

    expect(await screen.findByText(/SHA256:oldkeyoldkey/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Trust new key/ })).not.toBeInTheDocument();
  });

  it("offers exactly one remedy when the offline alert already shows it", async () => {
    vi.mocked(hostsApi.getHost).mockResolvedValue(host(PIN_ERROR));
    renderDetails(host(PIN_ERROR));

    expect(await screen.findByText(/SHA256:oldkeyoldkey/)).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: /Trust new key/ })).toHaveLength(1);
  });
});
