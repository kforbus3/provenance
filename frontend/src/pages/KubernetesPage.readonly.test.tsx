import "@testing-library/jest-dom/vitest";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, within } from "@testing-library/react";
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

beforeEach(() => {
  vi.restoreAllMocks();
  vi.spyOn(k8s, "listClusters").mockResolvedValue([cluster]);
  vi.spyOn(vault, "listVaultSecrets").mockResolvedValue([] as never);
  vi.spyOn(k8s, "listResources").mockResolvedValue([
    { name: "web", namespace: "default", status: "1/1", created: "1h" },
  ] as never);
});

// The resource browser is READ-ONLY on purpose.
//
// Changing a cluster goes through `kubectl` pointed at the audited proxy, not
// through buttons here. Provenance is not trying to be a Kubernetes dashboard —
// the upstream one is archived and its successor, Headlamp, is a SIG project
// that already does this job far better than a re-implementation would.
//
// Pinned by a test because it is a DECISION, and a decision recorded only as an
// absence is one somebody re-adds by accident.
describe("the resource browser is read-only", () => {
  it("offers no actions on deployments", async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><KubernetesPage /></QueryClientProvider>);
    fireEvent.click(await screen.findByRole("button", { name: "Browse resources" }));
    fireEvent.mouseDown(await screen.findByLabelText("Kind"));
    fireEvent.click(await screen.findByRole("option", { name: "deployments" }));
    await screen.findByText("web");

    for (const name of [/^Restart$/, /^Scale$/, /^Delete$/]) {
      expect(screen.queryByRole("button", { name })).not.toBeInTheDocument();
    }
    // Scoped to the resource table: the CLUSTER list above it has its own
    // "Actions" header, so an unscoped query matches that and passes for the
    // wrong reason.
    const resourceTable = screen.getByText("web").closest("table")!;
    expect(within(resourceTable).queryByText("Actions")).not.toBeInTheDocument();
  });
});
