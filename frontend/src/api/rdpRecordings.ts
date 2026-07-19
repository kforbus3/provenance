import { api } from "./client";

// Read-only access to recorded RDP (Windows desktop) sessions. Unlike SSH
// recordings (asciicast), these are Guacamole-protocol streams replayed with
// Guacamole.SessionRecording (/rdp/recordings).

export interface RDPRecording {
  id: string;
  hostId?: string;
  userId?: string;
  hostname: string;
  fleetUser: string;
  rdpUser: string;
  format: string;
  sizeBytes: number;
  durationMs: number;
  status: string;
  clientIp?: string;
  startedAt: string;
  endedAt?: string;
}

export async function listRdpRecordings(): Promise<RDPRecording[]> {
  const { data } = await api.get<{ recordings: RDPRecording[] }>("/api/v1/rdp/recordings");
  return data.recordings ?? [];
}

// downloadRdpRecordingBlob fetches the raw Guacamole recording so it can be fed to
// Guacamole.SessionRecording for in-app playback.
export async function downloadRdpRecordingBlob(id: string): Promise<Blob> {
  const res = await api.get(`/api/v1/rdp/recordings/${id}/download`, { responseType: "blob" });
  return res.data as Blob;
}

export async function deleteRdpRecording(id: string): Promise<void> {
  await api.delete(`/api/v1/rdp/recordings/${id}`);
}

export interface RecordingStats {
  count: number;
  bytes: number;
}

export async function rdpRecordingStats(): Promise<RecordingStats> {
  const { data } = await api.get<RecordingStats>("/api/v1/rdp/recordings/stats");
  return data;
}
