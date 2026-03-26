import type { HTTPEvent } from "h3";
import type {
  SessionConfigJWE,
  SessionHooksJWE,
  SessionJWE,
  SessionManager as BaseSessionManager,
  SessionData,
  SessionClaims,
  SessionUpdate,
  ExpiresIn,
} from "unjwt/adapters/h3v2";
import { updateJWESession, clearJWESession, useJWESession } from "unjwt/adapters/h3v2";
import { computeExpiresInSeconds } from "unjwt/utils";

/**
 * Extended session hooks for h3v2.
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
    event: HTTPEvent;
    config: SessionConfigJWE<T, MaxAge>;
    /** Destroy the session (delete cookie, reset state). */
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
   */
  onRefresh?(args: {
    session: SessionJWE<T, MaxAge> & { id: string; token: string };
    event: HTTPEvent;
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

/** Return type of {@link defineSession}. */
export type DefineSessionReturn<T extends SessionData> = (
  event: HTTPEvent,
) => Promise<SessionManager<T>>;

/**
 * Creates an encrypted session (JWE) composable with auto-refresh support.
 *
 * Returns a function that resolves the session for the current request.
 * The session is cached per-request by unjwt — calling the composable
 * multiple times in the same request is free.
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
  options: H3SessionOptions<T>,
): DefineSessionReturn<T> {
  const refreshAfter = options.refreshAfter ?? 0.75;

  const jweConfig = {
    name: options.name ?? "auth-session",
    maxAge: options.maxAge ?? ("7D" as const),
    key: options.key,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      ...options.cookie,
    } as const,
    jwe: options.jwe,
    hooks: {
      async onRead({ session, config, event, ...ctxRest }) {
        const clear = (): Promise<void> => clearJWESession(event, config);

        if (refreshAfter !== false && session.id) {
          const maxAgeSec = computeExpiresInSeconds(config.maxAge!);
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
                  event,
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
        await options.hooks?.onRead?.({ ...ctxRest, session, event, config, clear });
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

  return async (event: HTTPEvent): Promise<SessionManager<T>> => {
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
      const { HTTPError } = await import("h3v2");
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
