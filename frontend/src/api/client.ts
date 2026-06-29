import axios from "axios";

// Single axios instance. Credentials are sent so the HttpOnly refresh cookie
// flows automatically; the access token is attached by an interceptor once auth
// is wired (M2). The base URL is same-origin in dev (Vite proxy) and prod (nginx).
export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE ?? "",
  withCredentials: true,
});

let accessToken: string | null = null;
// Notified when the token changes via background refresh, so the auth store
// (and any ?token= consumers) stay in sync without a page reload.
let onTokenChange: ((t: string | null) => void) | null = null;

export function setAccessToken(token: string | null) {
  accessToken = token;
}

export function setTokenChangeHandler(fn: (t: string | null) => void) {
  onTokenChange = fn;
}

// getAccessToken exposes the in-memory token for streamed fetch() calls (large
// SFTP transfers) that bypass the axios instance.
export function getAccessToken(): string | null {
  return accessToken;
}

api.interceptors.request.use((cfg) => {
  if (accessToken) {
    cfg.headers.Authorization = `Bearer ${accessToken}`;
  }
  return cfg;
});

// The access token is short-lived (~15m). On a 401, transparently exchange the
// HttpOnly refresh cookie for a new token (single in-flight refresh) and retry
// the original request once — so long-running sessions don't fail mid-action.
let refreshing: Promise<string | null> | null = null;

function refreshAccessToken(): Promise<string | null> {
  if (!refreshing) {
    refreshing = api
      .post<{ accessToken?: string }>("/api/v1/auth/refresh")
      .then((r) => {
        const t = r.data.accessToken ?? null;
        accessToken = t;
        onTokenChange?.(t);
        return t;
      })
      .catch(() => {
        accessToken = null;
        onTokenChange?.(null);
        return null;
      })
      .finally(() => { refreshing = null; });
  }
  return refreshing;
}

api.interceptors.response.use(
  (resp) => resp,
  async (error) => {
    const cfg = error.config;
    const url: string = cfg?.url ?? "";
    const isAuthCall = url.includes("/auth/refresh") || url.includes("/auth/login");
    if (error.response?.status === 401 && cfg && !cfg._retry && !isAuthCall) {
      cfg._retry = true;
      const token = await refreshAccessToken();
      if (token) {
        cfg.headers = cfg.headers ?? {};
        cfg.headers.Authorization = `Bearer ${token}`;
        return api(cfg);
      }
    }
    return Promise.reject(error);
  },
);

export interface VersionInfo {
  version: string;
  environment?: string;
  appName?: string;
}

export async function getVersion(): Promise<VersionInfo> {
  const { data } = await api.get<VersionInfo>("/version");
  return data;
}
