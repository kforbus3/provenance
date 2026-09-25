import "@testing-library/jest-dom/vitest";
import { render, screen } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { CertificatesPage } from "./CertificatesPage";
import * as api from "../api/certificates";
import { useAuthStore } from "../store/auth";

// A rotation is trusted first and signs second. The page must say which key signs,
// which is pending, which hosts do not confirm the new key yet -- and offer the retire
// action that did not exist (every key ever created stayed trusted for ever).
describe("CA rotation on the Certificates page", () => {
  beforeEach(() => {
    vi.spyOn(useAuthStore.getState(), "has").mockReturnValue(true);
    vi.spyOn(api, "listCertificates").mockResolvedValue([]);
  });

  it("shows a pending rotation, the hosts holding it up, and what each key is doing", async () => {
    vi.spyOn(api, "listCAs").mockResolvedValue({ activeUserCA: "", cas: [
      { id: "new", kind: "user", algo: "ssh-ed25519", publicKey: "", fingerprint: "SHA256:new", active: true, createdAt: "2026-09-25T00:00:00Z" },
      { id: "old", kind: "user", algo: "ssh-ed25519", publicKey: "", fingerprint: "SHA256:old", active: true, createdAt: "2026-06-28T00:00:00Z", signingSince: "2026-06-28T00:00:00Z" },
    ] });
    vi.spyOn(api, "getCARotation").mockResolvedValue({
      signingId: "old", pendingId: "new", jumpTrustsPending: false, outOfSync: 1,
      hosts: [
        { hostId: "1", hostname: "vhost", inSync: true },
        { hostId: "2", hostname: "gitlab", inSync: false, error: "unreachable: dial jump host" },
      ],
    });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><CertificatesPage /></QueryClientProvider>);

    expect(await screen.findByText(/Rotation in progress: 1 of 2 hosts/)).toBeInTheDocument();
    expect(screen.getByText(/but the jump host does not yet/)).toBeInTheDocument();
    expect(screen.getByText(/gitlab — unreachable: dial jump host/)).toBeInTheDocument();
    expect(await screen.findByText("signing")).toBeInTheDocument();
    expect(screen.getByText("pending — trusted, not signing yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Abandon rotation" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Promote anyway" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rotation in progress" })).toBeDisabled();
  });

  it("offers to retire a key that no longer signs", async () => {
    vi.spyOn(api, "listCAs").mockResolvedValue({ activeUserCA: "", cas: [
      { id: "new", kind: "user", algo: "ssh-ed25519", publicKey: "", fingerprint: "SHA256:new", active: true, createdAt: "2026-09-25T00:00:00Z", signingSince: "2026-09-25T00:05:00Z" },
      { id: "old", kind: "user", algo: "ssh-ed25519", publicKey: "", fingerprint: "SHA256:old", active: true, createdAt: "2026-06-28T00:00:00Z", signingSince: "2026-06-28T00:00:00Z" },
    ] });
    vi.spyOn(api, "getCARotation").mockResolvedValue({ signingId: "new", outOfSync: 0, hosts: [] });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(<QueryClientProvider client={qc}><CertificatesPage /></QueryClientProvider>);
    expect(await screen.findByText("trusted — no longer signing")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retire" })).toBeInTheDocument();
  });
});
