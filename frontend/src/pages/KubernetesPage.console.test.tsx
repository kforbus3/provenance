import "@testing-library/jest-dom/vitest";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { KubernetesPage } from "./KubernetesPage";
import * as k8s from "../api/kubernetes";
import * as vault from "../api/vault";

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

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(k8s, "listClusters").mockResolvedValue([cluster]);
  vi.spyOn(vault, "listVaultSecrets").mockResolvedValue([] as never);
});

describe("the console is embedded, not linked", () => {
  it("frames Headlamp under this origin so the operator stays in Provenance", async () => {
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Open cluster UI" }));

    const frame = await screen.findByTitle("Kubernetes console for k3s-homelab");
    const src = frame.getAttribute("src") ?? "";
    // Same-origin: a link to another host with another login is the thing this
    // exists instead of.
    expect(src.startsWith("/headlamp/")).toBe(true);
    expect(src).not.toMatch(/^https?:\/\//);
  });

  it("says the calls are brokered and how to get a token", async () => {
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Open cluster UI" }));
    expect(await screen.findByText(/credential stays vaulted/i)).toBeInTheDocument();
    expect(screen.getByText(/limited to\s*Kubernetes/i)).toBeInTheDocument();
  });
});

describe("downloading a kubeconfig", () => {
  it("reports a refusal instead of silently producing nothing", async () => {
    vi.spyOn(k8s, "downloadKubeconfig").mockRejectedValue({
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
