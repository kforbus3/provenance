import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent } from "@testing-library/react";
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
