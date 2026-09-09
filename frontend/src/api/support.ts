import { getAccessToken } from "./client";
import { saveBlob } from "../lib/download";

// Download a host support bundle (a .tar.gz of diagnostics + logs). Generation
// runs over SSH and can take several seconds, so this uses fetch + a blob save
// with the in-memory access token (the backend gates it by Host.Scan + access).
export async function downloadSupportBundle(hostId: string, hostname: string): Promise<void> {
  const res = await fetch(`/api/v1/hosts/${hostId}/support-bundle`, {
    headers: { Authorization: `Bearer ${getAccessToken() ?? ""}` },
  });
  if (!res.ok) {
    let msg = "Could not collect support bundle.";
    try { msg = (await res.json()).error ?? msg; } catch { /* non-JSON body */ }
    throw new Error(msg);
  }
  const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
  saveBlob(await res.blob(), `${hostname}-support-${stamp}.tar.gz`);
}
