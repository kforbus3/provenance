import { api } from "./client";

// Read-only access to recorded SSH sessions and their asciicast recordings
// (/sessions, /sessions/{id}/recording).

export interface SSHSession {
  id: string;
  sessionId?: string;
  userId?: string;
  hostId?: string;
  username: string;
  hostname: string;
  certSerial?: number;
  status: string;
  startedAt: string;
  endedAt?: string;
  exitCode?: number;
  bytesIn: number;
  bytesOut: number;
  clientIp?: string;
  hasRecording: boolean;
}

export interface Recording {
  id: string;
  sshSessionId: string;
  format: string;
  sizeBytes: number;
  durationMs: number;
  sha256: string;
  createdAt: string;
}

export interface RecordingPayload {
  recording: Recording;
  cast: string;
}

export async function listSessions(): Promise<SSHSession[]> {
  const { data } = await api.get<{ sessions: SSHSession[] }>("/api/v1/sessions");
  return data.sessions;
}

export async function getRecording(id: string): Promise<RecordingPayload> {
  const { data } = await api.get<RecordingPayload>(`/api/v1/sessions/${id}/recording`);
  return data;
}

export interface SessionSearchResult {
  sessionId: string;
  username: string;
  hostname: string;
  startedAt: string;
  matchCount: number;
  snippets: string[];
}

export interface SessionSearchResponse {
  results: SessionSearchResult[];
  recordingsInSet: number;
  scanned: number;
  capped: boolean;
}

// searchSessionContent full-text searches recorded SSH session content (what was
// typed and shown), across the most recent recordings.
export async function searchSessionContent(q: string): Promise<SessionSearchResponse> {
  const { data } = await api.get<SessionSearchResponse>("/api/v1/sessions/search", { params: { q } });
  return {
    results: data.results ?? [],
    recordingsInSet: data.recordingsInSet ?? 0,
    scanned: data.scanned ?? 0,
    capped: data.capped ?? false,
  };
}

function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// recordingFilename builds a descriptive name: who ran the session + when.
function recordingFilename(s: SSHSession, ext: string): string {
  const d = new Date(s.startedAt);
  const p = (n: number) => String(n).padStart(2, "0");
  const ts = `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
  const user = (s.username || s.userId || "user").replace(/[^a-zA-Z0-9_.-]/g, "_");
  const host = (s.hostname || "host").replace(/[^a-zA-Z0-9_.-]/g, "_");
  return `session-${user}-${host}-${ts}.${ext}`;
}

// downloadRecordingCast exports the raw asciicast (.cast) file (for asciinema CLI).
export async function downloadRecordingCast(s: SSHSession): Promise<void> {
  const res = await api.get(`/api/v1/sessions/${s.id}/recording/download`, { responseType: "blob" });
  triggerDownload(res.data as Blob, recordingFilename(s, "cast"));
}

// downloadRecording exports a FULLY SELF-CONTAINED HTML file that plays the
// recording in any browser, completely offline — the player bundle and the cast
// are both embedded by the backend. Double-click the file to watch.
export async function downloadRecording(s: SSHSession): Promise<void> {
  const res = await api.get(`/api/v1/sessions/${s.id}/recording/player`, { responseType: "blob" });
  triggerDownload(res.data as Blob, recordingFilename(s, "html"));
}

export async function deleteRecording(id: string): Promise<void> {
  await api.delete(`/api/v1/sessions/${id}/recording`);
}

export interface RecordingStats {
  count: number;
  bytes: number;
}

export async function recordingStats(): Promise<RecordingStats> {
  const { data } = await api.get<RecordingStats>("/api/v1/recordings/stats");
  return data;
}

export async function pruneRecordings(olderThanDays: number): Promise<{ deleted: number; bytesReclaimed: number }> {
  const { data } = await api.post<{ deleted: number; bytesReclaimed: number }>(
    `/api/v1/recordings/prune?olderThanDays=${olderThanDays}`,
  );
  return data;
}
