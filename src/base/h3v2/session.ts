import { type HTTPEvent, HTTPError } from "h3v2";
import type {
  SessionConfigJWE,
  SessionHooksJWE,
  SessionManager as BaseSessionManager,
  SessionData,
  SessionClaims,
  ExpiresIn,
} from "unjwt/adapters/h3v2";
import { useJWESession } from "unjwt/adapters/h3v2";
import {
  DEFAULT_SESSION_NAME,
  DEFAULT_SESSION_MAX_AGE,
  DEFAULT_SECURE_COOKIE,
} from "../_internal/defaults.ts";
import { type RollingOption, resolveRolling } from "../_internal/session.ts";

/**
 * Session lifecycle hooks — unjwt's JWE session hooks, with the session always carrying a `maxAge`.
 *
 * `session` is the live manager, so `onRead` can act on it in place: `await session.update()` to
 * reissue (optionally with new data), `await session.clear()` to destroy it.
 */
export type H3SessionHooks<T extends SessionData = SessionClaims> = SessionHooksJWE<T, ExpiresIn>;

/**
 * Options for {@link defineSession}: unjwt's `SessionConfigJWE` with unauth's defaults, and a
 * `rolling` that can also be switched off.
 */
export interface H3SessionOptions<T extends SessionData> extends Omit<
  SessionConfigJWE<T, ExpiresIn>,
  "rolling"
> {
  /**
   * Reissue the session on read so `exp` slides with activity: `true` on every read, a duration
   * (e.g. `"15m"`) once less than that remains, `false` never.
   *
   * @default a quarter of `maxAge` remaining
   */
  rolling?: RollingOption;
}

/** Session manager type alias. Always has a defined `expiresAt`. */
export type SessionManager<T extends SessionData> = BaseSessionManager<T, ExpiresIn>;

/** Return type of {@link defineSession}. */
export type DefineSessionReturn<T extends SessionData> = (
  event: HTTPEvent,
) => Promise<SessionManager<T>>;

/**
 * Creates an encrypted session (JWE) composable with rolling expiry.
 *
 * Returns a function that resolves the session for the current request.
 * The session is cached per-request by unjwt — calling the composable
 * multiple times in the same request is free.
 *
 * @example
 * ```ts
 * const useSession = defineSession<{ userId: string; role: string }>({
 *   key: await generateJWK("A256GCM"),
 *   maxAge: "7D",
 *   hooks: {
 *     async onRead({ session }) {
 *       const user = await db.users.findById(session.data.userId);
 *       if (!user) return session.clear();
 *       if (user.role !== session.data.role) await session.update({ role: user.role });
 *     },
 *   },
 * });
 * ```
 *
 * @default name "auth-session"
 * @default maxAge "7D"
 * @default rolling a quarter of `maxAge` remaining
 * @default cookie `{ httpOnly: true, secure: true, sameSite: "lax", path: "/" }`
 */
export function defineSession<T extends SessionData>(
  options: H3SessionOptions<T>,
): DefineSessionReturn<T> {
  const { rolling, ...rest } = options;
  const maxAge = options.maxAge ?? DEFAULT_SESSION_MAX_AGE;

  const jweConfig = {
    ...rest,
    name: options.name ?? DEFAULT_SESSION_NAME,
    maxAge,
    rolling: resolveRolling(rolling, maxAge),
    cookie: options.cookie === false ? false : { ...DEFAULT_SECURE_COOKIE, ...options.cookie },
  } satisfies SessionConfigJWE<T, ExpiresIn>;

  return async (event: HTTPEvent): Promise<SessionManager<T>> => {
    return useJWESession<T, ExpiresIn>(event, jweConfig);
  };
}

/** Configuration for {@link requireSession} and {@link optionalSession}. */
export interface SessionMiddlewareConfig<T extends SessionData> {
  /**
   * Called after successful authentication, before the route handler.
   * Use for authorization checks (roles, permissions, etc.).
   * Throw to block the request.
   */
  onAuthenticated?(ctx: { session: SessionManager<T>; event: HTTPEvent }): void | Promise<void>;
}

/**
 * Middleware that requires an authenticated session.
 * Throws `HTTPError 401` if no valid session exists.
 *
 * @example
 * ```ts
 * app.get("/me", handler, { middleware: [requireSession(useSession)] });
 * ```
 */
export function requireSession<T extends SessionData>(
  useSession: DefineSessionReturn<T>,
  config?: SessionMiddlewareConfig<T>,
): (event: HTTPEvent) => Promise<void> {
  return async (event: HTTPEvent): Promise<void> => {
    const session = await useSession(event);
    if (!session.id) {
      throw new HTTPError("Unauthorized", { status: 401 });
    }
    await config?.onAuthenticated?.({ session, event });
  };
}

/**
 * Middleware that allows unauthenticated requests.
 * Resolves the session but does not throw if absent.
 * `onAuthenticated` only fires when a valid session exists.
 *
 * @example
 * ```ts
 * app.get("/feed", handler, { middleware: [optionalSession(useSession)] });
 * ```
 */
export function optionalSession<T extends SessionData>(
  useSession: DefineSessionReturn<T>,
  config?: SessionMiddlewareConfig<T>,
): (event: HTTPEvent) => Promise<void> {
  return async (event: HTTPEvent): Promise<void> => {
    const session = await useSession(event);
    if (session.id) {
      await config?.onAuthenticated?.({ session, event });
    }
  };
}
