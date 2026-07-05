import { api } from "./client";

// Multi-site federation. These endpoints exist only when the backend runs in
// hub mode; the mode probe lets the SPA show or hide the site dimension.

export interface FederationSite {
  id: string;
  name: string;
  status: string; // pending | active | revoked | error
  linkState: string; // up | down
  lagSeconds: number;
  apiVersion: string;
  lastSeenAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface JoinTokenResult {
  joinToken: string;
  hubFingerprint: string;
  env: Record<string, string>;
}

export interface FederatedHost {
  federatedId: string; // "{siteId}:{hostId}"
  siteId: string;
  hostId: string;
  status: string;
  host: unknown; // opaque snapshot of the site's host row
  cachedAt: string;
}

export async function getFederationMode(): Promise<string> {
  try {
    const { data } = await api.get<{ mode: string }>("/api/v1/federation/mode");
    return data.mode ?? "standalone";
  } catch {
    return "standalone";
  }
}

export async function listSites(): Promise<FederationSite[]> {
  const { data } = await api.get<{ sites: FederationSite[] }>("/api/v1/federation/sites");
  return data.sites ?? [];
}

export async function createJoinToken(siteName: string, ttlHours = 1): Promise<JoinTokenResult> {
  const { data } = await api.post<JoinTokenResult>("/api/v1/federation/sites/tokens", { siteName, ttlHours });
  return data;
}

export async function revokeSite(siteId: string): Promise<void> {
  await api.delete(`/api/v1/federation/sites/${siteId}`);
}

export async function rotateHubKey(): Promise<{ fingerprint: string; pushedToSites: number }> {
  const { data } = await api.post<{ fingerprint: string; pushedToSites: number }>(
    "/api/v1/federation/keys/rotate",
  );
  return data;
}

export async function listFederatedHosts(siteId?: string): Promise<FederatedHost[]> {
  const { data } = await api.get<{ hosts: FederatedHost[] }>("/api/v1/federation/cache/hosts", {
    params: siteId ? { site: siteId } : undefined,
  });
  return data.hosts ?? [];
}
