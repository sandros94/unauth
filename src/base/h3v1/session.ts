import { type H3Event, type H3EventContext, createError } from "h3";
import type {
  SessionConfigJWE,
  SessionHooksJWE,
  SessionManager as BaseSessionManager,
  SessionData,
  SessionClaims,
  ExpiresIn,
} from "unjwt/adapters/h3v1";
import { useJWESession } from "unjwt/adapters/h3v1";
import {
  DEFAULT_SESSION_NAME,
  DEFAULT_SESSION_MAX_AGE,
  DEFAULT_SECURE_COOKIE,
} from "../_internal/defaults.ts";
import { type RollingOption, resolveRolling } from "../_internal/session.ts";

/**
 * A request-like object unjwt's adapter accepts in place of a full `H3Event`.
 *
 * This is what makes a session resolvable outside a normal request — most usefully in a
 * WebSocket `upgrade` hook, where crossws hands over `{ url, headers, context }` (or a web
 * `Request`) rather than an `H3Event`. Such an event is **read-only**: unjwt refuses to write
 * cookies through it, so the session can be verified and decoded but never reissued or cleared,
 * and a `rolling` reissue is skipped with a warning.
 */
export type CompatEvent =
  | { request: { headers: Headers }; context: H3EventContext }
  | { headers: Headers; context: H3EventContext };

/** Any event this adapter can resolve a session from. */
export type SessionEvent = H3Event | CompatEvent;

/**
 * Session lifecycle hooks — unjwt's JWE session hooks, with the session always carrying a `maxAge`.
 *
 * `session` is the live manager, so `onRead` can act on it in place: `await session.update()` to
 * reissue (optionally with new data), `await session.clear()` to destroy it. Both throw
 * `ERR_SESSION_READONLY_EVENT` when the session was read through a {@link CompatEvent}; narrow
 * `event` with h3's `isEvent()` first when that matters.
 */
export type H3SessionHooks<T extends SessionData = SessionClaims> = SessionHooksJWE<
  T,
  ExpiresIn,
  SessionEvent
>;

/**
 * Options for {@link defineSession}: unjwt's `SessionConfigJWE` with unauth's defaults, and a
 * `rolling` that can also be switched off.
 */
export interface H3SessionOptions<T extends SessionData> extends Omit<
  SessionConfigJWE<T, ExpiresIn, SessionEvent>,
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

/**
 * Return type of {@link defineSession}.
 *
 * Accepts a {@link CompatEvent} as well as an `H3Event`, so a session can also be resolved from a
 * WebSocket upgrade — read-only, see {@link CompatEvent}.
 */
export type DefineSessionReturn<T extends SessionData> = (
  event: SessionEvent,
) => Promise<SessionManager<T>>;

/**
 * Creates an encrypted session (JWE) composable with rolling expiry.
 *
 * Returns a function that resolves the session for the current request.
 * The session is cached per-request by unjwt — calling the composable
 * multiple times in the same request is free.
 *
 * It also accepts a {@link CompatEvent}, so the same composable resolves a session inside a
 * WebSocket `upgrade` hook. That path is read-only: the session is verified and decoded, a
 * `rolling` reissue is skipped, and `update()` / `clear()` throw.
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
  } satisfies SessionConfigJWE<T, ExpiresIn, SessionEvent>;

  return async (event: SessionEvent): Promise<SessionManager<T>> => {
    return useJWESession<T, ExpiresIn, SessionEvent>(event, jweConfig);
  };
}

/** Configuration for {@link requireSession} and {@link optionalSession}. */
export interface SessionMiddlewareConfig<T extends SessionData> {
  /**
   * Called after successful authentication, before the route handler.
   * Use for authorization checks (roles, permissions, etc.).
   * Throw to block the request.
   */
  onAuthenticated?(ctx: { session: SessionManager<T>; event: H3Event }): void | Promise<void>;
}

/**
 * Middleware that requires an authenticated session.
 * Throws `createError` with status 401 if no valid session exists.
 *
 * @example
 * ```ts
 * app.use("/me", defineEventHandler({ onRequest: requireSession(useSession), handler }));
 * ```
 */
export function requireSession<T extends SessionData>(
  useSession: DefineSessionReturn<T>,
  config?: SessionMiddlewareConfig<T>,
): (event: H3Event) => Promise<void> {
  return async (event: H3Event): Promise<void> => {
    const session = await useSession(event);
    if (!session.id) {
      throw createError({ statusCode: 401, statusMessage: "Unauthorized" });
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
 * app.use("/feed", defineEventHandler({ onRequest: optionalSession(useSession), handler }));
 * ```
 */
export function optionalSession<T extends SessionData>(
  useSession: DefineSessionReturn<T>,
  config?: SessionMiddlewareConfig<T>,
): (event: H3Event) => Promise<void> {
  return async (event: H3Event): Promise<void> => {
    const session = await useSession(event);
    if (session.id) {
      await config?.onAuthenticated?.({ session, event });
    }
  };
}
