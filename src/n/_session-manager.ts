import type { ExpiresIn, SessionData, SessionManager } from "unjwt/session";
import { computeDurationInSeconds } from "unjwt/utils";
import { UnauthError } from "../_internal/error.ts";
import type {
  AuthSessionData,
  AuthSessionManager,
  AuthSessionRecord,
  AuthenticatedData,
  AuthenticatedSessionManager,
} from "./session.ts";

/** The claim `authenticate()` alone sets. */
export const AUTHENTICATED_AT = "authenticatedAt";

/** Wraps an unjwt session manager in the auth one; state stays live on `inner`. */
export function authSessionManager<TData extends AuthSessionRecord>(
  inner: SessionManager<AuthSessionData<TData>, ExpiresIn>,
): AuthSessionManager<TData> {
  const manager: AuthSessionManager<TData> = {
    get id() {
      return inner.id;
    },
    get createdAt() {
      return inner.createdAt;
    },
    get expiresAt() {
      return inner.expiresAt;
    },
    get data() {
      // A copy, so `authenticatedAt` cannot be written past `authenticate()`.
      const copy = { ...inner.data };
      Object.freeze(copy);
      return copy;
    },
    get token() {
      return inner.token;
    },
    update: async (update, options) => {
      await inner.update((live) => {
        const resolved =
          typeof update === "function" ? update(withoutReserved({ ...live })) : update;
        const patch = resolved ? withoutReserved(resolved) : {};
        const authenticatedAt = live[AUTHENTICATED_AT];
        return authenticatedAt === undefined
          ? patch
          : { ...patch, [AUTHENTICATED_AT]: authenticatedAt };
      }, options);
      return manager;
    },
    clear: async () => {
      await inner.clear();
      return manager;
    },
    authenticate: async (data, options) => {
      await inner.update(
        (old) => ({ ...withoutReserved(data), [AUTHENTICATED_AT]: nextAuthenticatedAt(old) }),
        options,
      );
      return manager;
    },
    requireRecent: (maxAge) => {
      const { authenticatedAt } = requireAuthenticated(manager).data;
      if (Date.now() - authenticatedAt > computeDurationInSeconds(maxAge) * 1000) {
        throw new UnauthError(
          `[unauth/n] The session authenticated more than ${String(maxAge)} ago; sign in again.`,
          "ERR_AUTHN_REAUTH_REQUIRED",
          { status: 401, cause: { authenticatedAt } },
        );
      }
    },
  };
  return manager;
}

/** `session` once it authenticated, else `ERR_AUTHN_UNAUTHENTICATED` (401). */
export function requireAuthenticated<TData extends AuthSessionRecord>(
  session: AuthSessionManager<TData>,
): AuthenticatedSessionManager<TData> {
  if (!isAuthenticatedSession(session)) {
    throw new UnauthError("[unauth/n] No authenticated session.", "ERR_AUTHN_UNAUTHENTICATED", {
      status: 401,
    });
  }
  return session;
}

/** Whether a persisted session's data carries `authenticatedAt`: narrows the manager. */
export function isAuthenticatedSession<TData extends AuthSessionRecord>(
  session: AuthSessionManager<TData>,
): session is AuthenticatedSessionManager<TData> {
  return session.id !== undefined && isAuthenticatedData(session.data);
}

/** `data` without `authenticatedAt`, which only `authenticate()` may set. */
export function withoutReserved<T extends object>(data: T): T {
  if (!Object.hasOwn(data, AUTHENTICATED_AT)) return data;
  const copy = { ...data };
  Reflect.deleteProperty(copy, AUTHENTICATED_AT);
  return copy;
}

/** Whether session data carries the `authenticatedAt` only `authenticate()` sets. */
function isAuthenticatedData<TData extends AuthSessionRecord>(
  data: SessionData<AuthSessionData<TData>>,
): data is AuthenticatedData<TData> {
  return typeof Reflect.get(data, AUTHENTICATED_AT) === "number";
}

/**
 * Now, or one past the previous value: every sign-in moves `authenticatedAt` forward, so
 * `onSignIn` can tell a sign-in from an `update()` even within one millisecond.
 */
function nextAuthenticatedAt(old: Record<string, unknown>): number {
  const previous = old[AUTHENTICATED_AT];
  return typeof previous === "number" ? Math.max(Date.now(), previous + 1) : Date.now();
}
