import { api } from "./client";

// What registries say is available for the images the fleet is running.
//
// Two independent signals, and they answer different questions:
//   latestTag — a newer version tag exists in the repository
//   a moved digest — the tag a host runs points at different bytes than the
//     host has, which is what a base-image rebuild looks like
//
// A tool that reported only the first would call a host current while it runs a
// months-old build of the same version number.

export interface ImageUpdateHost {
  hostId: string;
  hostname: string;
  digest?: string;
  container?: string;
  // Per host, not per image: mid-rollout some hosts have the new bytes and some
  // do not, and an image-level flag would hide exactly that.
  stale: boolean;
}

export interface ImageUpdate {
  repository: string;
  tag: string;
  // What the tag points at in the registry now.
  digest?: string;
  // A newer tag, when one was found AND could be ordered confidently. Empty is a
  // real answer; `note` says whether that means "nothing newer" or "these tags
  // cannot be ordered", which are different and must not look the same.
  latestTag?: string;
  note?: string;
  error?: string;
  checkedAt: string;
  hosts: ImageUpdateHost[];
}

export async function listContainerUpdates(): Promise<ImageUpdate[]> {
  const { data } = await api.get<{ updates: ImageUpdate[] }>("/api/v1/container-updates");
  return data.updates ?? [];
}

export async function checkContainerUpdates(): Promise<{ status: string; note?: string }> {
  const { data } = await api.post<{ status: string; note?: string }>(
    "/api/v1/container-updates/check");
  return data;
}
