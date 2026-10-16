/**
 * Framework-agnostic defaults shared by adapters.
 */

export const DEFAULT_SESSION_NAME = "auth-session";
export const DEFAULT_SESSION_MAX_AGE = "7D" as const;
/** `rolling` default: reissue once less than this fraction of `maxAge` remains. */
export const DEFAULT_ROLLING_WINDOW = 0.25;

export const DEFAULT_CSRF_NAME = "csrf";
export const DEFAULT_CSRF_HEADER = "x-csrf-token";
export const DEFAULT_PROTECTED_METHODS: string[] = ["POST", "PUT", "DELETE", "PATCH"];

export const DEFAULT_AT_NAME = "auth_at";
export const DEFAULT_RT_NAME = "auth_rt";

/** httpOnly cookie defaults — sessions and refresh tokens. */
export const DEFAULT_SECURE_COOKIE = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
} as const;

/** Client-readable cookie defaults — access tokens. */
export const DEFAULT_AT_COOKIE = {
  httpOnly: false,
  secure: true,
  sameSite: "lax",
  path: "/",
} as const;

/** Client-readable cookie defaults — CSRF tokens. */
export const DEFAULT_CSRF_COOKIE = {
  httpOnly: false,
  secure: true,
  sameSite: "lax",
  path: "/",
} as const;
