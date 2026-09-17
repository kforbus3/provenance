import "@testing-library/jest-dom/vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { KubernetesPage } from "./KubernetesPage";
import { useAuthStore } from "../store/auth";
import * as k8s from "../api/kubernetes";
import * as vault from "../api/vault";

// The embedded console has to be signed in BEFORE it renders, and the same
// signed-in console has to be reachable in an ordinary browser tab. Both are
// things only a mounted component shows: the ordering bug here is invisible to a
// unit test of the API layer, and was invisible in review.

vi.mock("../api/kubernetes", async () => {
  const actual = await vi.importActual<typeof k8s>("../api/kubernetes");
  return {
    ...actual,
    listClusters: vi.fn(),
    listResources: vi.fn(),
    downloadKubeconfig: vi.fn(),
    authorizeConsole: vi.fn(),
    consoleAuthorized: vi.fn(),
  };
});
vi.mock("../api/vault", async () => {
  const actual = await vi.importActual<typeof vault>("../api/vault");
  return { ...actual, listVaultSecrets: vi.fn() };
});

const cluster = {
  id: "c1", name: "k3s-homelab", apiServer: "https://k3s.example.com:6443",
  credentialId: "v1", credentialName: "k3s-homelab", insecureTls: false,
  namespace: "default", description: "", createdBy: "keith",
  createdAt: "", updatedAt: "",
} as unknown as k8s.K8sCluster;

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}><KubernetesPage /></QueryClientProvider>);
}

const openConsole = async () =>
  fireEvent.click(await screen.findByRole("button", { name: "Open cluster UI" }));

const iframe = () => document.querySelector('iframe[title="Kubernetes console for k3s-homelab"]');

let openSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(k8s.listClusters).mockResolvedValue([cluster]);
  vi.mocked(k8s.listResources).mockResolvedValue([]);
  vi.mocked(k8s.downloadKubeconfig).mockResolvedValue(undefined);
  vi.mocked(vault.listVaultSecrets).mockResolvedValue([] as never);
  // Default: the console's cookie is already good, so tests that are not about
  // the sign-in path get a rendered console without arranging one.
  vi.mocked(k8s.consoleAuthorized).mockResolvedValue(true);
  vi.mocked(k8s.authorizeConsole).mockResolvedValue(true);
  openSpy = vi.spyOn(window, "open").mockImplementation(() => null);
  useAuthStore.setState({
    user: { id: "u1", username: "keith" },
    permissions: ["Kubernetes.Access", "Kubernetes.Manage"],
    isSuperAdmin: false, loaded: true,
  } as never);
});
afterEach(() => openSpy.mockRestore());

describe("the console is embedded, not linked", () => {
  it("frames Headlamp under this origin so the operator stays in Provenance", async () => {
    renderPage();
    await openConsole();

    const frame = await screen.findByTitle("Kubernetes console for k3s-homelab");
    const src = frame.getAttribute("src") ?? "";
    // Same-origin: a link to another host with another login is the thing this
    // exists instead of. It is also what makes signing the console in possible at
    // all — the endpoint that sets its cookie is only reachable same-origin.
    expect(src.startsWith("/headlamp/")).toBe(true);
    expect(src).not.toMatch(/^https?:\/\//);
  });

  it("says the calls are brokered and recorded against the operator", async () => {
    renderPage();
    await openConsole();
    expect(await screen.findByText(/credential stays vaulted/i)).toBeInTheDocument();
    expect(screen.getByText(/limited to\s*Kubernetes/i)).toBeInTheDocument();
  });
});

describe("signing the console in", () => {
  // The ordering IS the feature. Headlamp reads its token when it boots, so an
  // iframe mounted before the cookie exists loads unauthenticated and sits on its
  // auth screen — the cookie arriving a moment later does not make it retry.
  it("does not mount the console until the token has been set", async () => {
    let release: (v: boolean) => void = () => {};
    vi.mocked(k8s.consoleAuthorized).mockResolvedValue(false);
    vi.mocked(k8s.authorizeConsole).mockReturnValue(
      new Promise<boolean>((res) => { release = res; }),
    );

    renderPage();
    await openConsole();
    expect(await screen.findByText(/Signing in to the console/)).toBeInTheDocument();
    expect(iframe()).toBeNull();

    release(true);
    await waitFor(() => expect(iframe()).not.toBeNull());
    expect(iframe()).toHaveAttribute("src", "/headlamp/c/k3s-homelab/");
  });

  // Reopening the console must not mint a new credential: minting supersedes the
  // previous token, so a component that minted on every open would invalidate the
  // cookie another tab or device is holding.
  it("reuses a cookie that still works instead of minting again", async () => {
    renderPage();
    await openConsole();
    await waitFor(() => expect(iframe()).not.toBeNull());
    expect(k8s.authorizeConsole).not.toHaveBeenCalled();
  });

  // Losing the ability to mint must not produce a console that silently fails.
  // Headlamp can still take a pasted token, so say so and render it.
  it("falls back to Headlamp's own prompt when Provenance will not mint", async () => {
    vi.mocked(k8s.consoleAuthorized).mockResolvedValue(false);
    vi.mocked(k8s.authorizeConsole).mockRejectedValue(new Error("403"));

    renderPage();
    await openConsole();
    expect(await screen.findByText(/could not mint a console token/)).toBeInTheDocument();
    await waitFor(() => expect(iframe()).not.toBeNull());
  });
});

describe("opening the console in a new tab", () => {
  // The new tab carries no token in its URL — it relies on the cookie set for
  // this origin.
  it("opens the same console path, with nothing secret in the URL", async () => {
    vi.mocked(k8s.consoleAuthorized).mockResolvedValue(false);

    renderPage();
    await openConsole();
    const btn = await screen.findByRole("button", { name: /Open in new tab/ });
    await waitFor(() => expect(btn).not.toBeDisabled());
    fireEvent.click(btn);

    expect(openSpy).toHaveBeenCalledWith("/headlamp/c/k3s-homelab/", "_blank", "noopener,noreferrer");
    expect(openSpy.mock.calls[0][0] as string).not.toMatch(/token|secret|bearer/i);
  });

  it("does not offer it before the console is signed in", async () => {
    vi.mocked(k8s.consoleAuthorized).mockResolvedValue(false);
    vi.mocked(k8s.authorizeConsole).mockReturnValue(new Promise<boolean>(() => {}));

    renderPage();
    await openConsole();
    expect(await screen.findByRole("button", { name: /Open in new tab/ })).toBeDisabled();
  });
});

describe("downloading a kubeconfig", () => {
  it("reports a refusal instead of silently producing nothing", async () => {
    vi.mocked(k8s.downloadKubeconfig).mockRejectedValue({
      response: { data: { error: "no clusters are registered, so a kubeconfig would reach nothing" } },
    });
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /download kubeconfig/i }));
    // A download button that does nothing visible is indistinguishable from a
    // browser that blocked the download.
    await waitFor(() =>
      expect(screen.getByText(/would reach nothing/i)).toBeInTheDocument());
  });
});
