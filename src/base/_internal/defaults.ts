/**
 * Framework-agnostic defaults shared by adapters.
 */

export const DEFAULT_SESSION_NAME = "auth-session";
export const DEFAULT_SESSION_MAX_AGE = "7D" as const;
export const DEFAULT_REFRESH_AFTER = 0.75;

export const DEFAULT_CSRF_NAME = "csrf";
export const DEFAULT_CSRF_HEADER = "x-csrf-token";
export const DEFAULT_PROTECTED_METHODS = ["POST", "PUT", "DELETE", "PATCH"];

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
