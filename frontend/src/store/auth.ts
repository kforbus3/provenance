import { create } from "zustand";
import { setAccessToken, setTokenChangeHandler } from "../api/client";
import * as authApi from "../api/auth";
import type { User } from "../api/auth";
import { authenticatePasskey } from "../api/webauthn";

interface AuthState {
  user: User | null;
  permissions: string[];
  accessToken: string | null;
  isSuperAdmin: boolean;
  loaded: boolean;
  // login returns {mfaRequired, challenge} when a second factor is needed, or
  // {mfaEnrollmentRequired, setupToken} when MFA is mandatory but not yet
  // enrolled; otherwise the session is established.
  login: (username: string, password: string) => Promise<{
    mfaRequired?: boolean; challenge?: string;
    mfaEnrollmentRequired?: boolean; setupToken?: string;
  }>;
  verifyMfa: (challenge: string, code: string) => Promise<void>;
  completeMfaSetup: (setupToken: string, code: string) => Promise<void>;
  verifyPasskey: (challenge: string) => Promise<void>;
  logout: () => Promise<void>;
  loadMe: () => Promise<void>;
  // restore re-establishes the session from the refresh cookie when there is no
  // in-memory access token (new tab / reload), then loads the profile.
  restore: () => Promise<void>;
  has: (perm: string) => boolean;
}

// Authentication store. The access token lives in memory only (never persisted);
// session continuity across reloads relies on the HttpOnly refresh cookie +
// loadMe(). Super Admins and the Admin.All wildcard satisfy every permission.
export const useAuthStore = create<AuthState>()((set, get) => ({
  user: null,
  permissions: [],
  accessToken: null,
  isSuperAdmin: false,
  loaded: false,

  login: async (username, password) => {
    const res = await authApi.login(username, password);
    if (res.mfaRequired) {
      return { mfaRequired: true, challenge: res.challenge };
    }
    if (res.mfaEnrollmentRequired) {
      return { mfaEnrollmentRequired: true, setupToken: res.setupToken };
    }
    setAccessToken(res.accessToken ?? null);
    set({ user: res.user ?? null, accessToken: res.accessToken ?? null });
    await get().loadMe();
    return {};
  },

  verifyMfa: async (challenge, code) => {
    const res = await authApi.mfaVerify(challenge, code);
    setAccessToken(res.accessToken ?? null);
    set({ user: res.user ?? null, accessToken: res.accessToken ?? null });
    await get().loadMe();
  },

  completeMfaSetup: async (setupToken, code) => {
    const res = await authApi.mfaSetupConfirm(setupToken, code);
    setAccessToken(res.accessToken ?? null);
    set({ user: res.user ?? null, accessToken: res.accessToken ?? null });
    await get().loadMe();
  },

  verifyPasskey: async (challenge) => {
    const res = await authenticatePasskey(challenge);
    setAccessToken(res.accessToken ?? null);
    set({ user: res.user ?? null, accessToken: res.accessToken ?? null });
    await get().loadMe();
  },

  logout: async () => {
    try {
      await authApi.logout();
    } finally {
      setAccessToken(null);
      set({
        user: null,
        permissions: [],
        accessToken: null,
        isSuperAdmin: false,
        loaded: true,
      });
    }
  },

  restore: async () => {
    if (!get().accessToken) {
      try {
        const res = await authApi.refreshSession();
        setAccessToken(res.accessToken ?? null);
        set({ accessToken: res.accessToken ?? null });
      } catch {
        /* no valid refresh cookie — loadMe will mark unauthenticated */
      }
    }
    await get().loadMe();
  },

  loadMe: async () => {
    try {
      const res = await authApi.me();
      set({
        user: res.user,
        permissions: res.permissions,
        isSuperAdmin: res.isSuperAdmin,
        loaded: true,
      });
    } catch {
      setAccessToken(null);
      set({
        user: null,
        permissions: [],
        accessToken: null,
        isSuperAdmin: false,
        loaded: true,
      });
    }
  },

  has: (perm) => {
    const { isSuperAdmin, permissions } = get();
    if (isSuperAdmin) return true;
    return permissions.includes("Admin.All") || permissions.includes(perm);
  },
}));

// Keep the store's token in sync with background token refreshes from the api
// client (so ?token= consumers like the report viewer use the fresh token).
setTokenChangeHandler((t) => useAuthStore.setState({ accessToken: t }));
