import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { NewRolloutDialog } from "./ImagingPage";
import * as imagingApi from "../api/imaging";
import * as hostsApi from "../api/hosts";
import * as adminApi from "../api/admin";

// Rollouts could only ever target the whole fleet or one group, though the
// backend has accepted a list of hosts all along: MachinesForTarget takes
// (groups, hosts, all) and the model carries TargetHosts. Only the dialog was
// missing, so "update this one machine" meant inventing a group for it.

vi.mock("../api/imaging", async () => {
  const actual = await vi.importActual<typeof imagingApi>("../api/imaging");
  return { ...actual, listBundles: vi.fn(), listMachines: vi.fn(), createRollout: vi.fn() };
});
vi.mock("../api/hosts", async () => {
  const actual = await vi.importActual<typeof hostsApi>("../api/hosts");
  return { ...actual, listHosts: vi.fn() };
});
vi.mock("../api/admin", async () => {
  const actual = await vi.importActual<typeof adminApi>("../api/admin");
  return { ...actual, listGroups: vi.fn() };
});

const HOSTS = [
  { id: "h1", hostname: "kiosk-01" },
  { id: "h2", hostname: "kiosk-02" },
  { id: "h3", hostname: "db-server" }, // no machine record — not a target
] as unknown as hostsApi.Host[];

function renderDialog() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <NewRolloutDialog open onClose={() => {}} onCreated={() => {}} setMsg={() => {}} />
    </QueryClientProvider>,
  );
}

describe("rollout targeting", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(imagingApi.listBundles).mockResolvedValue(
      { bundles: [{ name: "b.raucb", version: "1.4.0" }] } as never);
    vi.mocked(imagingApi.listMachines).mockResolvedValue({
      machines: [
        { id: "aa", hostId: "h1" }, { id: "bb", hostId: "h2" },
        { id: "cc", hostId: null }, // unpaired: cannot be reached through a host
      ],
      counts: {}, versions: {}, interval: 300,
    } as never);
    vi.mocked(hostsApi.listHosts).mockResolvedValue({ hosts: HOSTS } as never);
    vi.mocked(adminApi.listGroups).mockResolvedValue([{ id: "g1", name: "kiosks" }] as never);
  });

  const pickBundle = async () => {
    fireEvent.mouseDown(screen.getByLabelText(/bundle/i));
    fireEvent.click(await screen.findByText(/b\.raucb/));
  };

  it("offers hosts as a target, alongside the fleet and a group", async () => {
    renderDialog();
    expect(await screen.findByRole("button", { name: /whole fleet/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^group$/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^hosts$/i })).toBeInTheDocument();
  });

  // The point of the feature: one machine, without inventing a group for it.
  it("sends the chosen host ids and neither a group nor the whole fleet", async () => {
    renderDialog();
    await pickBundle();
    fireEvent.click(screen.getByRole("button", { name: /^hosts$/i }));
    fireEvent.mouseDown(screen.getByLabelText(/^hosts/i));
    fireEvent.click(await screen.findByText("kiosk-01"));
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));

    await waitFor(() => expect(imagingApi.createRollout).toHaveBeenCalled());
    const body = vi.mocked(imagingApi.createRollout).mock.calls[0][0];
    expect(body.hosts).toEqual(["h1"]);
    expect(body.groups).toEqual([]);
    expect(body.all).toBe(false);
  });

  // A host with no machine record resolves to nothing, so offering it would be
  // offering a target that is refused on submit — a worse way to learn the same
  // fact than not listing it.
  it("lists only hosts that are paired with a machine", async () => {
    renderDialog();
    fireEvent.click(await screen.findByRole("button", { name: /^hosts$/i }));
    fireEvent.mouseDown(screen.getByLabelText(/^hosts/i));
    expect(await screen.findByText("kiosk-01")).toBeInTheDocument();
    expect(screen.getByText("kiosk-02")).toBeInTheDocument();
    expect(screen.queryByText("db-server")).toBeNull();
  });

  it("still supports the whole fleet, which is what it defaults to", async () => {
    renderDialog();
    await pickBundle();
    fireEvent.click(screen.getByRole("button", { name: /^create$/i }));
    await waitFor(() => expect(imagingApi.createRollout).toHaveBeenCalled());
    const body = vi.mocked(imagingApi.createRollout).mock.calls[0][0];
    expect(body.all).toBe(true);
    expect(body.hosts).toEqual([]);
  });

  // Submitting an empty host list would create a rollout that targets nothing.
  it("will not submit hosts mode with nothing chosen", async () => {
    renderDialog();
    await pickBundle();
    fireEvent.click(screen.getByRole("button", { name: /^hosts$/i }));
    expect(screen.getByRole("button", { name: /^create$/i })).toBeDisabled();
  });
});
