import { type H3Event, createError, isEvent } from "h3v1";
import type {
  SessionConfigJWE,
  SessionHooksJWE,
  SessionJWE,
  SessionManager as BaseSessionManager,
  SessionData,
  SessionClaims,
  SessionUpdate,
  ExpiresIn,
} from "unjwt/adapters/h3v1";
import { updateJWESession, clearJWESession, useJWESession } from "unjwt/adapters/h3v1";
import { computeDurationInSeconds } from "unjwt/utils";
import {
  DEFAULT_SESSION_NAME,
  DEFAULT_SESSION_MAX_AGE,
  DEFAULT_REFRESH_AFTER,
  DEFAULT_SECURE_COOKIE,
} from "../_internal/defaults.ts";

/**
 * A request-like object unjwt's adapter accepts in place of a full `H3Event`.
 *
 * This is what makes a session resolvable outside a normal request — most usefully in a
 * WebSocket `upgrade` hook, where crossws hands over `{ url, headers, context }` (or a web
 * `Request`) rather than an `H3Event`. Such an event is **read-only**: unjwt refuses to write
 * cookies through it, so the session can be verified and decoded but never re-issued or cleared.
 */
export type CompatEvent =
  | { request: { headers: Headers }; context: any }
  | { headers: Headers; context: any };

/** Any event this adapter can resolve a session from. */
export type SessionEvent = H3Event | CompatEvent;

/**
 * Whether cookies can be written through this event.
 *
 * Only a real `H3Event` carries the response to set them on; a {@link CompatEvent} does not, and
 * unjwt throws rather than pretending otherwise.
 */
function canWriteCookies(event: SessionEvent): event is H3Event {
  return isEvent(event);
}

/**
 * Extended session hooks for h3v1.
 *
 * Extends unjwt's `SessionHooksJWE` with:
 * - `onRead` augmented with a `clear()` function
 * - `onRefresh` for auto-refresh with `refresh()` and `clear()` functions
 */
export interface H3SessionHooks<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends Omit<SessionHooksJWE<T, MaxAge>, "onRead"> {
  /**
   * Fires after the session is successfully read and validated.
   * Receives a `clear()` function to destroy the session if needed
   * (e.g., the user is banned).
   *
   * Not called when `onRefresh` fires (they are mutually exclusive).
   */
  onRead?(args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    /**
     * May be a {@link CompatEvent} — narrow with `readOnly` before doing anything that needs a
     * real `H3Event` (writing cookies, `event.waitUntil`, h3 request helpers).
     */
    event: SessionEvent;
    config: SessionConfigJWE<T, MaxAge>;
    /**
     * `true` when the session was read through a {@link CompatEvent} (e.g. a WebSocket upgrade).
     * `clear()` cannot work in that case — check this before attempting one.
     */
    readOnly: boolean;
    /** Destroy the session (delete cookie, reset state). Throws when {@link readOnly}. */
    clear(): Promise<void>;
  }): void | Promise<void>;

  /**
   * Fires when the session has crossed the `refreshAfter` threshold.
   *
   * Call `refresh()` to re-issue the session:
   * - `refresh()` — sliding window (same data, new jti/iat/exp)
   * - `refresh({ role: 'admin' })` — merge partial data
   * - `refresh(old => ({ count: old.count + 1 }))` — callback update
   *
   * Don't call `refresh()` to skip. Call `clear()` to destroy.
   * Throwing forwards to `onError`.
   *
   * If no `onRefresh` hook is registered, the default behavior
   * is automatic sliding window.
   *
   * **Never fires on a read-only {@link CompatEvent}** — a session that cannot be re-issued is
   * treated as a plain read and dispatched to `onRead` instead. So `event` here is always a real
   * `H3Event`, and any work this hook does (a user lookup, an audit write) is never wasted on a
   * refresh that cannot land.
   */
  onRefresh?(args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    event: H3Event;
    config: SessionConfigJWE<T, MaxAge>;
    /** Re-issue the session. Accepts the same update format as `session.update()`. */
    refresh(update?: SessionUpdate<T>): Promise<void>;
    /** Destroy the session (delete cookie, reset state). */
    clear(): Promise<void>;
  }): void | Promise<void>;
}

/**
 * Options for {@link defineSession}.
 *
 * Extends unjwt's `SessionConfigJWE` with `refreshAfter` and the
 * extended {@link H3SessionHooks}.
 */
export interface H3SessionOptions<T extends SessionData> extends Omit<
  SessionConfigJWE<T>,
  "hooks"
> {
  /**
   * When to auto-refresh the session, as a ratio of `maxAge` (0 to 1).
   * For example, `0.75` means refresh after 75% of the session's
   * lifetime has elapsed.
   *
   * Set to `false` to disable auto-refresh.
   * @default 0.75
   */
  refreshAfter?: number | false;
  /** Lifecycle hooks. */
  hooks?: H3SessionHooks<T>;
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
  event: SessionEvent
) => Promise<SessionManager<T>>;

/**
 * Creates an encrypted session (JWE) composable with auto-refresh support.
 *
 * Returns a function that resolves the session for the current request.
 * The session is cached per-request by unjwt — calling the composable
 * multiple times in the same request is free.
 *
 * It also accepts a {@link CompatEvent}, so the same composable resolves a session inside a
 * WebSocket `upgrade` hook. That path is read-only: the session is verified and decoded, auto-
 * refresh is skipped (see {@link H3SessionHooks.onRefresh}), and `update()` / `clear()` throw.
 *
 * @example
 * ```ts
 * const useSession = defineSession<{ userId: string }>({
 *   key: await generateJWK("A256GCM"),
 *   maxAge: "7D",
 *   hooks: {
 *     async onRefresh({ session, refresh }) {
 *       const user = await db.users.findById(session.data.userId);
 *       await refresh({ userId: user.id, role: user.role });
 *     },
 *   },
 * });
 * ```
 *
 * @default name "auth-session"
 * @default maxAge "7D"
 * @default refreshAfter 0.75
 * @default cookie `{ httpOnly: true, secure: true, sameSite: "lax", path: "/" }`
 */
export function defineSession<T extends SessionData>(
  options: H3SessionOptions<T>
): DefineSessionReturn<T> {
  const refreshAfter = options.refreshAfter ?? DEFAULT_REFRESH_AFTER;

  const jweConfig = {
    name: options.name ?? DEFAULT_SESSION_NAME,
    maxAge: options.maxAge ?? DEFAULT_SESSION_MAX_AGE,
    key: options.key,
    cookie: {
      ...DEFAULT_SECURE_COOKIE,
      ...options.cookie,
    } as const,
    jwe: options.jwe,
    hooks: {
      async onRead({ session, config, event, ...ctxRest }) {
        const clear = (): Promise<void> => clearJWESession(event, config);
        const writable = canWriteCookies(event);

        // A read-only event (WebSocket upgrade) cannot carry a Set-Cookie, so refreshing is
        // impossible by construction — not a failure. Attempting it anyway would throw out of
        // unjwt, land in `onError`, and report a routine socket connection as a session error.
        // Fall through to `onRead` instead: the session still resolves, and the next ordinary
        // request slides it.
        if (refreshAfter !== false && session.id && writable) {
          const maxAgeSec = computeDurationInSeconds(config.maxAge!);
          const maxAgeMs = maxAgeSec * 1000;
          const elapsed = Date.now() - session.createdAt;
          const threshold = maxAgeMs * refreshAfter;

          if (elapsed >= threshold) {
            const refresh = async (update?: SessionUpdate<T>): Promise<void> => {
              await updateJWESession(event, config, update);
            };

            if (options.hooks?.onRefresh) {
              try {
                await options.hooks.onRefresh({
                  session,
                  event: event as H3Event,
                  config,
                  refresh,
                  clear,
                });
              } catch (err) {
                await options.hooks.onError?.({
                  session,
                  error: err,
                  event,
                  config,
                });
              }
            } else {
              try {
                await updateJWESession(event, config);
              } catch (err) {
                await options.hooks?.onError?.({
                  session,
                  error: err,
                  event,
                  config,
                });
              }
            }
            return;
          }
        }
        await options.hooks?.onRead?.({
          ...ctxRest,
          session,
          event,
          config,
          readOnly: !writable,
          clear,
        });
      },
      async onUpdate(ctx) {
        await options.hooks?.onUpdate?.(ctx);
      },
      async onClear(ctx) {
        await options.hooks?.onClear?.(ctx);
      },
      async onExpire(ctx) {
        await options.hooks?.onExpire?.(ctx);
      },
      async onError(ctx) {
        await options.hooks?.onError?.(ctx);
      },
    },
  } satisfies SessionConfigJWE<T, ExpiresIn>;

  return async (event: SessionEvent): Promise<SessionManager<T>> => {
    return useJWESession<T, typeof jweConfig.maxAge>(event, jweConfig);
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
  config?: SessionMiddlewareConfig<T>
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
  config?: SessionMiddlewareConfig<T>
): (event: H3Event) => Promise<void> {
  return async (event: H3Event): Promise<void> => {
    const session = await useSession(event);
    if (session.id) {
      await config?.onAuthenticated?.({ session, event });
    }
  };
}
