import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock the axios client so the API wrappers can be tested in isolation.
vi.mock("./client", () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}));

import { api } from "./client";
import { getHostAccess, addHostUser, removeHostUser, deleteHost } from "./hosts";

const mockedGet = api.get as unknown as ReturnType<typeof vi.fn>;
const mockedPost = api.post as unknown as ReturnType<typeof vi.fn>;
const mockedDelete = api.delete as unknown as ReturnType<typeof vi.fn>;

describe("getHostAccess", () => {
  beforeEach(() => vi.clearAllMocks());

  it("defaults missing groups/users to empty arrays", async () => {
    mockedGet.mockResolvedValue({ data: {} });
    const r = await getHostAccess("h1");
    expect(r.groups).toEqual([]);
    expect(r.users).toEqual([]);
    expect(mockedGet).toHaveBeenCalledWith("/api/v1/hosts/h1/access");
  });

  it("passes through groups and users when present", async () => {
    mockedGet.mockResolvedValue({
      data: { groups: ["ops"], users: [{ id: "u1", username: "bob" }] },
    });
    const r = await getHostAccess("h1");
    expect(r.groups).toEqual(["ops"]);
    expect(r.users).toHaveLength(1);
    expect(r.users[0].username).toBe("bob");
  });
});

describe("host user grants", () => {
  beforeEach(() => vi.clearAllMocks());

  it("adds a user to a host via the scoped endpoint", async () => {
    mockedPost.mockResolvedValue({ data: {} });
    await addHostUser("host-1", "user-9");
    expect(mockedPost).toHaveBeenCalledWith("/api/v1/hosts/host-1/users/user-9");
  });

  it("removes a user from a host via the scoped endpoint", async () => {
    mockedDelete.mockResolvedValue({ data: {} });
    await removeHostUser("host-1", "user-9");
    expect(mockedDelete).toHaveBeenCalledWith("/api/v1/hosts/host-1/users/user-9");
  });
});

// Teardown removes Fleet's accounts and SSH trust from the machine, so the
// parameter has to be sent only when the operator asked for it. A default that
// leaked "true" would decommission hosts an operator only meant to un-inventory.
describe("deleteHost", () => {
  beforeEach(() => vi.clearAllMocks());

  it("does not request teardown by default", async () => {
    mockedDelete.mockResolvedValue({ data: { teardownRequested: false } });
    await deleteHost("host-1");
    expect(mockedDelete).toHaveBeenCalledWith("/api/v1/hosts/host-1");
  });

  it("does not request teardown when explicitly declined", async () => {
    mockedDelete.mockResolvedValue({ data: { teardownRequested: false } });
    await deleteHost("host-1", false);
    expect(mockedDelete).toHaveBeenCalledWith("/api/v1/hosts/host-1");
  });

  it("requests teardown only when asked", async () => {
    mockedDelete.mockResolvedValue({ data: { teardownRequested: true, teardownStarted: true } });
    const r = await deleteHost("host-1", true);
    expect(mockedDelete).toHaveBeenCalledWith("/api/v1/hosts/host-1?teardown=true");
    expect(r.teardownStarted).toBe(true);
  });

  it("surfaces a teardown that could not start", async () => {
    mockedDelete.mockResolvedValue({
      data: { teardownRequested: true, teardownStarted: false, teardownError: "host unreachable" },
    });
    const r = await deleteHost("host-1", true);
    expect(r.teardownStarted).toBe(false);
    expect(r.teardownError).toBe("host unreachable");
  });

  it("survives a response with no body", async () => {
    mockedDelete.mockResolvedValue({ data: undefined });
    await expect(deleteHost("host-1", true)).resolves.toEqual({ teardownRequested: true });
  });
});
