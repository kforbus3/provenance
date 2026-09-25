import "@testing-library/jest-dom/vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { StacksPage } from "./StacksPage";
import * as api from "../api/stacks";
import type { ContainerStack } from "../api/stacks";

// Keycloak's stored copy was the plain-HTTP file while the host ran TLS, both at
// revision 5, and this page said "deployed r5". A Deploy would have taken Keycloak
// down. The page must say the file was changed on the host.
describe("a stack changed on its host", () => {
  it("is flagged, and counted in the drift banner", async () => {
    const st: ContainerStack = {
      id: "k", hostId: "h", hostname: "identity", name: "keycloak", path: "/opt/stacks/keycloak",
      revision: 5, enabled: true, deployedRevision: 5, deployState: "deployed",
      createdAt: "", updatedAt: "", hostDiffers: true,
    } as ContainerStack;
    vi.spyOn(api, "listStacks").mockResolvedValue([st]);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><MemoryRouter><StacksPage /></MemoryRouter></QueryClientProvider>);
    fireEvent.click(await screen.findByRole("tab", { name: /managed stacks/i }));
    expect(await screen.findByText("changed on host (r5)")).toBeInTheDocument();
    expect(screen.getByText(/changed on the host: deploying would overwrite that change/)).toBeInTheDocument();
  });
});
