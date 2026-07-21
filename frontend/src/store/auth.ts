import { create } from "zustand";
import { setAccessToken, setTokenChangeHandler, setActiveTenant, getActiveTenant } from "../api/client";
import * as authApi from "../api/auth";
import type { User } from "../api/auth";
import { authenticatePasskey } from "../api/webauthn";

interface AuthState {
  user: User | null;
  permissions: string[];
  accessToken: string | null;
  isSuperAdmin: boolean;
  loaded: boolean;
  // Multi-tenancy.
  multiTenancy: boolean;
  isProviderAdmin: boolean;
  tenantId: string | null;
  activeTenant: string | null; // the customer tenant a provider admin switched into (null = own)
  switchTenant: (id: string | null) => void;
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
  multiTenancy: false,
  isProviderAdmin: false,
  tenantId: null,
  activeTenant: getActiveTenant(),

  // switchTenant sets (or clears) the customer tenant a provider admin is acting within.
  // The X-Fleet-Tenant header follows; a reload keeps the selection.
  switchTenant: (id) => {
    setActiveTenant(id);
    set({ activeTenant: id });
  },

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
      setActiveTenant(null);
      set({
        user: null,
        permissions: [],
        accessToken: null,
        isSuperAdmin: false,
        multiTenancy: false,
        isProviderAdmin: false,
        tenantId: null,
        activeTenant: null,
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
      // A non-provider-admin must never carry a tenant-switch header.
      if (!res.isProviderAdmin && getActiveTenant()) {
        setActiveTenant(null);
      }
      set({
        user: res.user,
        permissions: res.permissions,
        isSuperAdmin: res.isSuperAdmin,
        multiTenancy: !!res.multiTenancy,
        isProviderAdmin: !!res.isProviderAdmin,
        tenantId: res.tenantId ?? null,
        activeTenant: res.isProviderAdmin ? getActiveTenant() : null,
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
// A null token means the silent refresh failed — the session expired or was
// reaped (idle/absolute timeout). Clear the user so ProtectedRoute redirects to
// /login instead of stranding them on a page whose actions all 401.
setTokenChangeHandler((t) =>
  useAuthStore.setState(t ? { accessToken: t } : { accessToken: null, user: null }));
