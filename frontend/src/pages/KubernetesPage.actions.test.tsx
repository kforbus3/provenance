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

async function openBrowser() {
  renderPage();
  fireEvent.click(await screen.findByRole("button", { name: "Browse resources" }));
}

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(k8s, "listClusters").mockResolvedValue([cluster]);
  vi.spyOn(vault, "listVaultSecrets").mockResolvedValue([] as never);
});

describe("write actions appear only where there is an obvious one", () => {
  it("offers Restart and Scale on deployments", async () => {
    vi.spyOn(k8s, "listResources").mockResolvedValue([
      { name: "web", namespace: "default", status: "1/1", created: "1h" },
    ] as never);
    await openBrowser();
    fireEvent.mouseDown(await screen.findByLabelText("Kind"));
    fireEvent.click(await screen.findByRole("option", { name: "deployments" }));
    expect(await screen.findByRole("button", { name: "Restart" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scale" })).toBeInTheDocument();
  });

  it("offers nothing on nodes — cordon and drain are not one-click operations", async () => {
    vi.spyOn(k8s, "listResources").mockResolvedValue([
      { name: "k3s", namespace: "", status: "Ready", created: "1d" },
    ] as never);
    await openBrowser();
    fireEvent.mouseDown(await screen.findByLabelText("Kind"));
    fireEvent.click(await screen.findByRole("option", { name: "nodes" }));
    await screen.findByText("k3s");
    expect(screen.queryByRole("button", { name: "Restart" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Delete$/ })).not.toBeInTheDocument();
  });
});

describe("a refusal names the system that refused", () => {
  it("attributes a 403 to the cluster's RBAC, not to Provenance", async () => {
    vi.spyOn(k8s, "listResources").mockResolvedValue([
      { name: "web", namespace: "default", status: "1/1", created: "1h" },
    ] as never);
    vi.spyOn(k8s, "restartDeployment").mockRejectedValue({ response: { status: 403 } });
    await openBrowser();
    fireEvent.mouseDown(await screen.findByLabelText("Kind"));
    fireEvent.click(await screen.findByRole("option", { name: "deployments" }));
    fireEvent.click(await screen.findByRole("button", { name: "Restart" }));
    // Sending someone to Provenance's permissions for a cluster-side refusal
    // wastes the one piece of information the error actually carried.
    await waitFor(() =>
      expect(screen.getByText(/that is a decision on the cluster, not in Provenance/i))
        .toBeInTheDocument());
  });
});
