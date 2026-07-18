import { api } from "./client";

// Mirrors backend models.User (json tags). Only fields surfaced by the API are
// declared; optional ones map to backend `omitempty`.
export interface User {
  id: string;
  username: string;
  email?: string;
  displayName: string;
  isSuperAdmin: boolean;
  isDisabled: boolean;
  emailVerified: boolean;
  mustChangePassword: boolean;
  lockedUntil?: string;
  lastLoginAt?: string;
  createdAt: string;
  updatedAt: string;
  roles?: string[];
  groups?: string[];
}

export interface LoginResponse {
  // Present on success:
  accessToken?: string;
  accessExpiresAt?: string;
  csrfToken?: string;
  user?: User;
  mustChangePassword?: boolean;
  // Present when a second factor is required:
  mfaRequired?: boolean;
  challenge?: string;
  // Present when MFA is mandatory but the user has not enrolled one yet. The
  // setupToken authorizes one-time enrollment, after which login completes.
  mfaEnrollmentRequired?: boolean;
  setupToken?: string;
}

export interface MfaMethod {
  id: string;
  kind: string;
  label: string;
  confirmed: boolean;
  createdAt: string;
}

// refreshSession exchanges the HttpOnly refresh cookie for a new access token.
// Used to restore a session in a freshly-opened tab or after a reload.
export async function refreshSession(): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>("/api/v1/auth/refresh");
  return data;
}

export async function mfaVerify(challenge: string, code: string): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>("/api/v1/auth/mfa/verify", { challenge, code });
  return data;
}

export async function mfaList(): Promise<MfaMethod[]> {
  const { data } = await api.get<{ methods: MfaMethod[] }>("/api/v1/auth/mfa");
  return data.methods;
}

export async function mfaEnroll(): Promise<{ secret: string; otpauthUrl: string }> {
  const { data } = await api.post<{ secret: string; otpauthUrl: string }>("/api/v1/auth/mfa/totp/enroll");
  return data;
}

export async function mfaConfirm(code: string): Promise<void> {
  await api.post("/api/v1/auth/mfa/totp/confirm", { code });
}

export async function mfaDelete(id: string): Promise<void> {
  await api.delete(`/api/v1/auth/mfa/${id}`);
}

// MFA recovery codes: one-time backup codes usable in place of TOTP/WebAuthn.
export async function recoveryStatus(): Promise<{ remaining: number }> {
  const { data } = await api.get<{ remaining: number }>("/api/v1/auth/mfa/recovery-codes");
  return data;
}

export async function generateRecoveryCodes(): Promise<string[]> {
  const { data } = await api.post<{ codes: string[] }>("/api/v1/auth/mfa/recovery-codes");
  return data.codes ?? [];
}

// Forced-enrollment flow (when MFA is mandatory but the user has no factor).
// Gated by the login setupToken rather than a session.
export async function mfaSetupBegin(setupToken: string): Promise<{ secret: string; otpauthUrl: string }> {
  const { data } = await api.post<{ secret: string; otpauthUrl: string }>(
    "/api/v1/auth/mfa/setup/begin", { setupToken });
  return data;
}

export async function mfaSetupConfirm(setupToken: string, code: string): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>("/api/v1/auth/mfa/setup/confirm", { setupToken, code });
  return data;
}

export interface MeResponse {
  user: User;
  permissions: string[];
  isSuperAdmin: boolean;
}

export interface BootstrapStatus {
  bootstrapAvailable: boolean;
}

export interface BootstrapInitParams {
  username: string;
  email: string;
  displayName: string;
  password: string;
}

export interface BootstrapInitResponse {
  status: string;
  user: User;
}

export async function bootstrapStatus(): Promise<BootstrapStatus> {
  const { data } = await api.get<BootstrapStatus>("/api/v1/bootstrap/status");
  return data;
}

export async function bootstrapInit(
  params: BootstrapInitParams,
): Promise<BootstrapInitResponse> {
  const { data } = await api.post<BootstrapInitResponse>(
    "/api/v1/bootstrap/init",
    params,
  );
  return data;
}

export async function login(
  username: string,
  password: string,
): Promise<LoginResponse> {
  const { data } = await api.post<LoginResponse>("/api/v1/auth/login", {
    username,
    password,
  });
  return data;
}

export async function me(): Promise<MeResponse> {
  const { data } = await api.get<MeResponse>("/api/v1/auth/me");
  return data;
}

export async function logout(): Promise<void> {
  await api.post("/api/v1/auth/logout");
}

export async function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<void> {
  await api.post("/api/v1/auth/change-password", {
    currentPassword,
    newPassword,
  });
}
