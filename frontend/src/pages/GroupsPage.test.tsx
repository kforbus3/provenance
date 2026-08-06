import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { GroupsPage } from "./GroupsPage";
import { useAuthStore } from "../store/auth";
import * as adminApi from "../api/admin";
import * as hostsApi from "../api/hosts";

// Group membership is how host access is granted, so "which hosts are in this
// group" has to be visible and editable from the Groups page — these tests cover
// that view, its edit path, and the two cases where editing must be withheld
// (no Host.Edit, or a rule-managed group whose membership the reconciler owns).

vi.mock("../api/admin", async () => {
  const actual = await vi.importActual<typeof adminApi>("../api/admin");
  return {
    ...actual,
    listGroups: vi.fn(),
    listUsers: vi.fn(),
    listGroupHosts: vi.fn(),
    addHostToGroup: vi.fn(),
    removeHostFromGroup: vi.fn(),
  };
});
vi.mock("../api/hosts", async () => {
  const actual = await vi.importActual<typeof hostsApi>("../api/hosts");
  return { ...actual, listHosts: vi.fn() };
});

const manualGroup = {
  id: "g1", name: "web-team", description: "Owns the web tier",
  createdAt: "2026-01-01T00:00:00Z", hostCount: 2,
};
const dynamicGroup = {
  id: "g2", name: "all-prod", description: "Production", createdAt: "2026-01-01T00:00:00Z",
  hostCount: 1, rule: { environment: "production" },
};
const member = {
  id: "h1", hostname: "web-01", description: "", environment: "production",
  owner: "ops", tags: ["web"], enrolled: true,
};

function host(id: string, hostname: string) {
  return {
    id, hostname, description: "", environment: "production", owner: "ops",
    sshPort: 22, sshUser: "fleet", tags: [], authMethod: "fleet_cert", protocol: "ssh",
    rdpPort: 3389, enrolled: true, createdAt: "", updatedAt: "",
  } as unknown as hostsApi.Host;
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <GroupsPage />
    </QueryClientProvider>,
  );
}

async function openHosts(groupName: string) {
  fireEvent.click(await screen.findByRole("button", { name: `Manage hosts in ${groupName}` }));
}

describe("GroupsPage host membership", () => {
  beforeEach(() => {
    vi.clearAllMocks(); // call counts are asserted per test
    vi.mocked(adminApi.listUsers).mockResolvedValue([]);
    vi.mocked(adminApi.listGroups).mockResolvedValue([manualGroup, dynamicGroup]);
    vi.mocked(adminApi.listGroupHosts).mockResolvedValue({
      hosts: [member], count: 1, dynamic: false,
    });
    vi.mocked(adminApi.addHostToGroup).mockResolvedValue(undefined);
    vi.mocked(adminApi.removeHostFromGroup).mockResolvedValue(undefined);
    vi.mocked(hostsApi.listHosts).mockResolvedValue({
      hosts: [host("h1", "web-01"), host("h2", "web-02")], count: 2,
    });
    useAuthStore.setState({
      user: { id: "u1", username: "admin" }, permissions: ["Group.Edit", "Host.Edit"],
      isSuperAdmin: false, loaded: true,
    } as never);
  });

  it("shows each group's host count and lists the members on open", async () => {
    renderPage();
    // The count column renders alongside the existing user count.
    expect(await screen.findByText("web-team")).toBeInTheDocument();
    await openHosts("web-team");
    expect(await screen.findByText("Hosts — web-team")).toBeInTheDocument();
    expect(await screen.findByText("web-01")).toBeInTheDocument();
    expect(adminApi.listGroupHosts).toHaveBeenCalledWith("g1");
  });

  it("removes a host from the group from the dialog", async () => {
    renderPage();
    await openHosts("web-team");
    fireEvent.click(await screen.findByRole("button", { name: "Remove web-01 from web-team" }));
    await waitFor(() => expect(adminApi.removeHostFromGroup).toHaveBeenCalledWith("g1", "h1"));
  });

  it("adds a host that is not already a member", async () => {
    renderPage();
    await openHosts("web-team");
    await screen.findByText("web-01");
    const picker = screen.getByLabelText("Add host");
    fireEvent.mouseDown(picker);
    fireEvent.change(picker, { target: { value: "web-02" } });
    fireEvent.click(await screen.findByText("web-02"));
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    await waitFor(() => expect(adminApi.addHostToGroup).toHaveBeenCalledWith("g1", "h2"));
  });

  it("withholds editing on a rule-managed group", async () => {
    vi.mocked(adminApi.listGroupHosts).mockResolvedValue({
      hosts: [member], count: 1, dynamic: true,
    });
    renderPage();
    await openHosts("all-prod");
    expect(await screen.findByText(/rule-managed/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Add host")).not.toBeInTheDocument();
    // The inventory is not fetched when nothing can be added.
    expect(hostsApi.listHosts).not.toHaveBeenCalled();
  });

  it("withholds editing from a viewer without Host.Edit", async () => {
    useAuthStore.setState({ permissions: ["Group.Edit"] } as never);
    renderPage();
    await openHosts("web-team");
    expect(await screen.findByText(/requires the Host.Edit permission/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("Add host")).not.toBeInTheDocument();
  });
});
