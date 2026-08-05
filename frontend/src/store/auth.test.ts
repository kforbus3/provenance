import { describe, it, expect, beforeEach } from "vitest";
import { useAuthStore } from "./auth";

// The permission check the whole UI gates on. It is not the security boundary —
// the backend enforces authorization on every route — but it decides what a user
// is shown, and a wrong answer here either leaks the existence of things they
// cannot use or hides things they can.
describe("useAuthStore.has", () => {
  beforeEach(() => {
    useAuthStore.setState({ isSuperAdmin: false, permissions: [] });
  });

  it("grants exactly what was granted", () => {
    useAuthStore.setState({ permissions: ["Hosts.Read", "Sessions.Connect"] });
    const { has } = useAuthStore.getState();
    expect(has("Hosts.Read")).toBe(true);
    expect(has("Sessions.Connect")).toBe(true);
    expect(has("Hosts.Delete")).toBe(false);
  });

  it("does not treat a permission as a prefix of another", () => {
    useAuthStore.setState({ permissions: ["Hosts.Read"] });
    const { has } = useAuthStore.getState();
    // "Hosts.ReadWrite" starts with a granted string; substring matching here
    // would hand out a permission nobody granted.
    expect(has("Hosts.ReadWrite")).toBe(false);
    expect(has("Hosts")).toBe(false);
  });

  it("lets Admin.All and super admins through", () => {
    useAuthStore.setState({ permissions: ["Admin.All"] });
    expect(useAuthStore.getState().has("Anything.At.All")).toBe(true);

    useAuthStore.setState({ isSuperAdmin: true, permissions: [] });
    expect(useAuthStore.getState().has("Anything.At.All")).toBe(true);
  });

  it("grants nothing to a signed-out caller", () => {
    const { has } = useAuthStore.getState();
    expect(has("Hosts.Read")).toBe(false);
    expect(has("Admin.All")).toBe(false);
  });
});
