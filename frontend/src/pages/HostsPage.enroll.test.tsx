import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { EnrollCredsDialog } from "./HostsPage";
import { useAuthStore } from "../store/auth";
import * as hostsApi from "../api/hosts";

// The enrollment dialog hands the operator a command to run in their own
// terminal. Both no-install methods are only usable if that command is
// copy-paste runnable — the SSH-agent block used to print a literal
// "<YOUR_TOKEN>" with no copy button, leaving no way to discover the session
// token (it lives in memory, never in storage). These cover both blocks.

vi.mock("../api/hosts", async () => {
  const actual = await vi.importActual<typeof hostsApi>("../api/hosts");
  return { ...actual, nextWGAddress: vi.fn() };
});

const host = {
  id: "670a279b-0115-4c61-ae13-0bcee4efae6c", hostname: "web-01", description: "",
  environment: "production", owner: "ops", sshPort: 22, sshUser: "fleet", tags: [],
  authMethod: "fleet_cert", protocol: "ssh", rdpPort: 3389, enrolled: false,
  createdAt: "", updatedAt: "",
} as unknown as hostsApi.Host;

function renderDialog() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <EnrollCredsDialog host={host} onClose={() => {}} onSubmit={() => {}} onPipeFinish={() => {}} />
    </QueryClientProvider>,
  );
}

describe("EnrollCredsDialog bootstrap commands", () => {
  beforeEach(() => {
    vi.mocked(hostsApi.nextWGAddress).mockResolvedValue({
      address: "10.9.0.5", jumpEndpoint: "vpn.example.com:51820",
    } as unknown as Awaited<ReturnType<typeof hostsApi.nextWGAddress>>);
    useAuthStore.setState({ accessToken: "eyJ-session-token" });
  });

  it("fills the live session token into the SSH-agent command", () => {
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /SSH agent/ }));

    const cmd = screen.getByText(/fleet-enroll-agent/).textContent ?? "";
    expect(cmd).toContain("-token eyJ-session-token");
    expect(cmd).not.toContain("<YOUR_TOKEN>");
    // The host id and bootstrap user come from the dialog, not the operator.
    expect(cmd).toContain(`-host ${host.id}`);
    expect(cmd).toContain("-bootstrap-user root");
  });

  it("tracks the SSH user and via-jump choice in the SSH-agent command", () => {
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /SSH agent/ }));
    fireEvent.change(screen.getByLabelText(/SSH user on the host/), {
      target: { value: "opsadmin" },
    });
    fireEvent.click(screen.getByRole("checkbox", { name: /through the jump host/ }));

    const cmd = screen.getByText(/fleet-enroll-agent/).textContent ?? "";
    expect(cmd).toContain("-bootstrap-user opsadmin");
    expect(cmd).toContain("-via-jump");
  });

  it("offers a copy button for the SSH-agent command", async () => {
    const writeText = vi.fn();
    Object.assign(navigator, { clipboard: { writeText } });
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /SSH agent/ }));
    fireEvent.click(screen.getByRole("button", { name: /Copy command/ }));

    expect(writeText).toHaveBeenCalledWith(expect.stringContaining("-token eyJ-session-token"));
  });

  it("fills the live session token into the no-install pipe command", () => {
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /No install/ }));

    const cmd = screen.getByText(/curl -fsSL/).textContent ?? "";
    expect(cmd).toContain("Bearer eyJ-session-token");
    expect(cmd).not.toContain("<YOUR_TOKEN>");
  });

  it("runs the no-install script over a TTY so sudo can prompt for a password", () => {
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /No install/ }));
    fireEvent.change(screen.getByLabelText(/Your SSH target/), {
      target: { value: "opsadmin@web-01" },
    });

    const cmd = screen.getByText(/curl -fsSL/).textContent ?? "";
    // Piping the script into sudo's stdin with no terminal is what produced
    // "sudo: a terminal is required to read the password" on hosts without
    // NOPASSWD, so the script must land first and run over a second `ssh -t`.
    expect(cmd).not.toMatch(/\|\s*ssh \S+ sudo/);
    expect(cmd).toContain("| ssh opsadmin@web-01 'cat > ~/fleet-enroll.sh'");
    expect(cmd).toContain("&& ssh -t opsadmin@web-01 'sudo sh ~/fleet-enroll.sh");
  });
});

// The VPN overlay choice used to reach only the over-SSH enrollment request: the
// no-install flow fetches its script by URL, and that URL carried the endpoint but
// not the overlay. Picking OpenVPN and getting a WireGuard host back is what that
// looks like from the operator's side.
describe("EnrollCredsDialog no-install VPN overlay", () => {
  beforeEach(() => {
    vi.mocked(hostsApi.nextWGAddress).mockResolvedValue({
      address: "10.9.0.5", jumpEndpoint: "vpn.example.com:51820",
    } as unknown as Awaited<ReturnType<typeof hostsApi.nextWGAddress>>);
    useAuthStore.setState({ accessToken: "eyJ-session-token" });
  });

  function pickOverlay(label: RegExp) {
    fireEvent.mouseDown(screen.getByRole("combobox", { name: /VPN overlay/ }));
    fireEvent.click(screen.getByRole("option", { name: label }));
  }

  it("builds the bootstrap command for the selected overlay", () => {
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /No install/ }));
    pickOverlay(/^OpenVPN/);

    const cmd = screen.getByText(/curl -fsSL/).textContent ?? "";
    expect(cmd).toContain("overlay=openvpn");
    expect(cmd).toContain(`/hosts/${host.id}/enroll/script`);
  });

  it("leaves the overlay out of the command when the deployment default is used", () => {
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /No install/ }));

    const cmd = screen.getByText(/curl -fsSL/).textContent ?? "";
    expect(cmd).not.toContain("overlay=");
  });

  it("asks for no host public key under a certificate overlay", () => {
    const onPipeFinish = vi.fn();
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <EnrollCredsDialog host={host} onClose={() => {}} onSubmit={() => {}} onPipeFinish={onPipeFinish} />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("radio", { name: /No install/ }));
    pickOverlay(/^OpenVPN/);

    // OpenVPN authenticates with the certificate embedded in the script, so there is
    // no key printed to paste — a required field here can never be satisfied and the
    // operator can never finish the enrollment.
    expect(screen.queryByLabelText(/Host public key/)).not.toBeInTheDocument();
    const finish = screen.getByRole("button", { name: /Finish enrollment/ });
    expect(finish).toBeEnabled();
    fireEvent.click(finish);
    // No key, and the resolved transport travels with it so the progress dialog can
    // name what is being provisioned rather than always saying WireGuard.
    expect(onPipeFinish).toHaveBeenCalledWith("", "openvpn");
  });

  it("follows the deployment default when the operator leaves the dropdown alone", async () => {
    // On an OpenVPN-by-default install, "Deployment default" IS a certificate
    // overlay — the dialog has to resolve it the same way the backend does, or it
    // sits there demanding a key the script never prints.
    vi.mocked(hostsApi.nextWGAddress).mockResolvedValue({
      address: "10.9.0.5", jumpEndpoint: "vpn.example.com:1194", overlay: "openvpn",
    } as unknown as Awaited<ReturnType<typeof hostsApi.nextWGAddress>>);
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /No install/ }));

    expect(await screen.findByText(/OpenVPN client certificate/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/Host public key/)).not.toBeInTheDocument();
    // The URL still omits the overlay: the backend resolves the default, including a
    // per-host one this dialog can't see.
    expect(screen.getByText(/curl -fsSL/).textContent ?? "").not.toContain("overlay=");
  });

  it("says a host will be renumbered when the choice moves it to another overlay", async () => {
    // The two overlays are separate pools, so a switch always changes the host's
    // address. Discovering that after clicking Enroll — when the old address has
    // already been released — is the wrong time to learn it.
    vi.mocked(hostsApi.nextWGAddress).mockResolvedValue({
      nextWgAddress: "10.100.0.9", subnet: "10.100.0.0/24",
      jumpEndpoint: "vpn.example.com:51820", overlay: "wireguard",
      overlays: [
        { name: "wireguard", subnet: "10.100.0.0/24", jumpIp: "10.100.0.1", port: 51820, protocol: "udp" },
        { name: "openvpn", subnet: "10.101.0.0/24", jumpIp: "10.101.0.1", port: 1194, protocol: "udp" },
      ],
      nextAddress: { wireguard: "10.100.0.9", openvpn: "10.101.0.4" },
    } as unknown as Awaited<ReturnType<typeof hostsApi.nextWGAddress>>);

    const enrolled = { ...host, enrolled: true, overlay: "wireguard", wgAddress: "10.100.0.27" } as hostsApi.Host;
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <EnrollCredsDialog host={enrolled} onClose={() => {}} onSubmit={() => {}} onPipeFinish={() => {}} />
      </QueryClientProvider>,
    );
    // Wait for the plans to arrive before switching, so the notice is rendered
    // from real data rather than the pre-fetch fallback.
    await screen.findByText(/must be open on the firewall/);
    pickOverlay(/^OpenVPN/);

    const notice = (await screen.findByText(/renumbered/)).textContent ?? "";
    expect(notice).toContain("10.100.0.27");
    expect(notice).toContain("10.101.0.0/24");
    expect(notice).toContain("10.101.0.4");
  });

  it("shows which pool and port a fresh host will use", async () => {
    vi.mocked(hostsApi.nextWGAddress).mockResolvedValue({
      nextWgAddress: "10.100.0.9", subnet: "10.100.0.0/24",
      jumpEndpoint: "vpn.example.com:51820", overlay: "wireguard",
      overlays: [
        { name: "wireguard", subnet: "10.100.0.0/24", jumpIp: "10.100.0.1", port: 51820, protocol: "udp" },
        { name: "openvpn", subnet: "10.101.0.0/24", jumpIp: "10.101.0.1", port: 1194, protocol: "udp" },
      ],
      nextAddress: { wireguard: "10.100.0.9", openvpn: "10.101.0.4" },
    } as unknown as Awaited<ReturnType<typeof hostsApi.nextWGAddress>>);
    renderDialog();
    pickOverlay(/^OpenVPN/);

    // The port matters operationally: it has to be open on the firewall, and it is
    // NOT the port in the endpoint field.
    const notice = (await screen.findByText(/must be open on the firewall/)).textContent ?? "";
    expect(notice).toContain("10.101.0.0/24");
    expect(notice).toContain("1194/udp");
    expect(notice).not.toContain("renumbered");
  });

  it("moves the endpoint port to the selected overlay's", async () => {
    // OpenVPN ignores the port typed here and always dials the deployment's OpenVPN
    // port, so showing WireGuard's invites an operator to hand-edit a value that was
    // never used — which is exactly what happened.
    vi.mocked(hostsApi.nextWGAddress).mockResolvedValue({
      nextWgAddress: "10.100.0.9", subnet: "10.100.0.0/24",
      jumpEndpoint: "vpn.example.com:51820", overlay: "wireguard",
      overlays: [
        { name: "wireguard", subnet: "10.100.0.0/24", jumpIp: "10.100.0.1", port: 51820, protocol: "udp" },
        { name: "openvpn", subnet: "10.101.0.0/24", jumpIp: "10.101.0.1", port: 1194, protocol: "udp" },
      ],
      nextAddress: { wireguard: "10.100.0.9", openvpn: "10.101.0.4" },
    } as unknown as Awaited<ReturnType<typeof hostsApi.nextWGAddress>>);
    renderDialog();

    const endpoint = await screen.findByLabelText(/Jump host VPN endpoint/);
    await waitFor(() => expect(endpoint).toHaveValue("vpn.example.com:51820"));

    pickOverlay(/^OpenVPN/);
    await waitFor(() => expect(endpoint).toHaveValue("vpn.example.com:1194"));

    // ...and back, so the field is never left describing the wrong transport.
    pickOverlay(/^WireGuard$/);
    await waitFor(() => expect(endpoint).toHaveValue("vpn.example.com:51820"));
  });

  it("hands the progress dialog the transport being provisioned", () => {
    // "Provisioning WireGuard…" was hard-coded, so it was wrong for every OpenVPN
    // enrollment — on screen, while the operator watched it happen.
    const onSubmit = vi.fn();
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <EnrollCredsDialog host={host} onClose={() => {}} onSubmit={onSubmit} onPipeFinish={() => {}} />
      </QueryClientProvider>,
    );
    pickOverlay(/^OpenVPN/);
    fireEvent.change(screen.getByLabelText(/^SSH password$/), { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: /^Enroll$/ }));

    // The REQUEST still carries the explicit choice; the second argument is the
    // resolved transport, for display only.
    expect(onSubmit).toHaveBeenCalledWith(
      expect.objectContaining({ overlay: "openvpn" }),
      "openvpn",
    );
  });

  it("still requires the pasted key under WireGuard", () => {
    renderDialog();
    fireEvent.click(screen.getByRole("radio", { name: /No install/ }));
    pickOverlay(/^WireGuard$/);

    expect(screen.getByLabelText(/Host public key/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Finish enrollment/ })).toBeDisabled();
  });
});
