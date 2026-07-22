import { api, getAccessToken, scopedURL } from "./client";

export interface SftpEntry {
  name: string;
  size: number;
  isDir: boolean;
  mode: string;
  modTime: string;
}

export interface SftpListing {
  path: string;
  entries: SftpEntry[];
}

export type ProgressFn = (loaded: number, total: number) => void;

export async function listDir(hostId: string, path: string): Promise<SftpListing> {
  const { data } = await api.get<SftpListing>(`/api/v1/hosts/${hostId}/sftp/list`, {
    params: { path },
  });
  return data;
}

// readTextFile fetches a remote text file's contents for the in-browser editor.
// The backend rejects files that are too large or binary.
export async function readTextFile(hostId: string, path: string): Promise<{ content: string; size: number }> {
  const { data } = await api.get<{ content: string; size: number }>(`/api/v1/hosts/${hostId}/sftp/read`, {
    params: { path },
  });
  return data;
}

// writeTextFile overwrites a remote text file, taking an on-host backup first
// (unless backup=false). Returns the backup path the server created (if any).
export async function writeTextFile(
  hostId: string, path: string, content: string, backup = true,
): Promise<{ backup: string }> {
  const { data } = await api.post<{ backup: string }>(`/api/v1/hosts/${hostId}/sftp/write`, {
    path, content, backup,
  });
  return data;
}

// uploadFile streams a file to the host with progress. `name` may include a
// relative subpath (folder uploads); the backend creates intermediate dirs.
export async function uploadFile(
  hostId: string,
  dir: string,
  file: File,
  name: string,
  onProgress?: ProgressFn,
  signal?: AbortSignal,
): Promise<void> {
  await api.post(`/api/v1/hosts/${hostId}/sftp/upload`, file, {
    params: { path: dir, name },
    headers: { "Content-Type": "application/octet-stream" },
    onUploadProgress: (e) => onProgress?.(e.loaded, e.total ?? file.size),
    signal,
  });
}

interface SavePickerWindow {
  showSaveFilePicker?: (opts: { suggestedName?: string }) => Promise<FileSystemFileHandle>;
}

// streamToDisk fetches url and writes the response to disk. With the File System
// Access API it streams straight to the chosen file (no memory cap); otherwise
// it falls back to a Blob. Reports progress when Content-Length is known.
async function streamToDisk(
  url: string,
  suggestedName: string,
  onProgress?: ProgressFn,
  signal?: AbortSignal,
): Promise<void> {
  const token = getAccessToken();
  const res = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    credentials: "include",
    signal,
  });
  if (!res.ok || !res.body) throw new Error(`download failed: ${res.status}`);
  const total = Number(res.headers.get("Content-Length") ?? 0);
  const reader = res.body.getReader();
  let received = 0;

  const picker = (window as unknown as SavePickerWindow).showSaveFilePicker;
  if (picker) {
    let handle: FileSystemFileHandle;
    try {
      handle = await picker({ suggestedName });
    } catch {
      await reader.cancel();
      return; // user cancelled the save dialog
    }
    const writable = await handle.createWritable();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        await writable.write(value);
        received += value.byteLength;
        onProgress?.(received, total);
      }
    } finally {
      await writable.close();
    }
    return;
  }

  const chunks: BlobPart[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.byteLength;
    onProgress?.(received, total);
  }
  const blobUrl = URL.createObjectURL(new Blob(chunks));
  const a = document.createElement("a");
  a.href = blobUrl;
  a.download = suggestedName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(blobUrl);
}

export function downloadFile(
  hostId: string,
  path: string,
  onProgress?: ProgressFn,
  signal?: AbortSignal,
): Promise<void> {
  const url = scopedURL(`/api/v1/hosts/${hostId}/sftp/download?path=${encodeURIComponent(path)}`);
  return streamToDisk(url, path.split("/").pop() ?? "download", onProgress, signal);
}

// downloadDir streams a remote directory as a .tar archive (recursive).
export function downloadDir(
  hostId: string,
  path: string,
  onProgress?: ProgressFn,
  signal?: AbortSignal,
): Promise<void> {
  const url = scopedURL(`/api/v1/hosts/${hostId}/sftp/download-dir?path=${encodeURIComponent(path)}`);
  const base = path.split("/").filter(Boolean).pop() ?? "archive";
  return streamToDisk(url, `${base}.tar`, onProgress, signal);
}
