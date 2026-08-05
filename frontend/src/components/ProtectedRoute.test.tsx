import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router-dom";
import { describe, it, expect, beforeEach, vi } from "vitest";
import { ProtectedRoute } from "./ProtectedRoute";
import { useAuthStore } from "../store/auth";

// The guard in front of every authenticated page. The backend is what actually
// enforces access — but this decides whether a signed-out visitor lands on the
// login page or on a rendered page, and whether a user without a permission is
// shown the thing they cannot use.

function renderGuard(permission?: string) {
  return render(
    <MemoryRouter initialEntries={["/secret"]}>
      <Routes>
        <Route element={<ProtectedRoute permission={permission} />}>
          <Route path="/secret" element={<div>the protected page</div>} />
        </Route>
        <Route path="/login" element={<div>the login page</div>} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ProtectedRoute", () => {
  beforeEach(() => {
    // restore() is called whenever the session has not been loaded; stub it so
    // a test that wants "not loaded yet" does not race a real network call.
    useAuthStore.setState({
      user: null,
      permissions: [],
      isSuperAdmin: false,
      loaded: true,
      restore: vi.fn(),
    } as never);
  });

  it("sends a signed-out visitor to the login page", () => {
    renderGuard();
    expect(screen.getByText("the login page")).toBeInTheDocument();
    expect(screen.queryByText("the protected page")).not.toBeInTheDocument();
  });

  it("waits rather than redirecting while the session is still being restored", () => {
    useAuthStore.setState({ loaded: false } as never);
    renderGuard();
    // Neither destination: redirecting here would bounce a signed-in user to
    // the login page on every reload, before their session has been restored.
    expect(screen.queryByText("the login page")).not.toBeInTheDocument();
    expect(screen.queryByText("the protected page")).not.toBeInTheDocument();
  });

  it("renders the page for a signed-in user when no permission is required", () => {
    useAuthStore.setState({ user: { id: "1", username: "alice" } } as never);
    renderGuard();
    expect(screen.getByText("the protected page")).toBeInTheDocument();
  });

  it("refuses a user who lacks the required permission", () => {
    useAuthStore.setState({
      user: { id: "1", username: "alice" },
      permissions: ["Hosts.Read"],
    } as never);
    renderGuard("Admin.Users");
    expect(screen.getByText(/403/)).toBeInTheDocument();
    expect(screen.queryByText("the protected page")).not.toBeInTheDocument();
  });

  it("admits a user who holds it", () => {
    useAuthStore.setState({
      user: { id: "1", username: "alice" },
      permissions: ["Admin.Users"],
    } as never);
    renderGuard("Admin.Users");
    expect(screen.getByText("the protected page")).toBeInTheDocument();
  });

  it("shows the password-change gate instead of any protected page", () => {
    useAuthStore.setState({
      user: { id: "1", username: "alice", mustChangePassword: true },
      permissions: ["Admin.Users"],
    } as never);
    renderGuard("Admin.Users");
    // The backend blocks every non-auth endpoint for such an account, so the
    // page behind this would be empty at best and misleading at worst.
    expect(screen.queryByText("the protected page")).not.toBeInTheDocument();
  });
});
