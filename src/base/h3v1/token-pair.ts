import { type H3Event, createError } from "h3v1";
import type {
  SessionConfigJWE,
  SessionConfigJWS,
  SessionManager as BaseSessionManager,
  SessionData,
  SessionClaims,
  SessionUpdate,
  ExpiresIn,
} from "unjwt/adapters/h3v1";
import { useJWSSession, useJWESession, getJWESession, updateJWSSession } from "unjwt/adapters/h3v1";
import {
  DEFAULT_AT_NAME,
  DEFAULT_RT_NAME,
  DEFAULT_AT_COOKIE,
  DEFAULT_SECURE_COOKIE,
} from "../_internal/defaults.ts";
import type { SessionSnapshot as _SessionSnapshot } from "../_internal/token-pair.ts";

/** Session manager type alias for token pair sessions. Always has a defined `expiresAt`. */
export type TokenPairSessionManager<T extends SessionData> = BaseSessionManager<T, ExpiresIn>;

type SessionSnapshot<T extends SessionData> = _SessionSnapshot<SessionData<T>>;

/**
 * The resolved token pair.
 *
 * `access` and `refresh` are the underlying unjwt session managers
 * exposed directly — calling `.update()` or `.clear()` on them
 * bypasses unauth hooks (intentional escape hatch for advanced users).
 *
 * `issue()` and `revoke()` are the coordinated methods that go
 * through the full hook lifecycle.
 */
export interface TokenPair<TAccess extends SessionData, TRefresh extends SessionData> {
  /** The access token session manager (JWS, short-lived, client-readable). */
  readonly access: TokenPairSessionManager<TAccess>;
  /** The refresh token session manager (JWE, long-lived, encrypted). */
  readonly refresh: TokenPairSessionManager<TRefresh>;
  /** Coordinated issue: creates RT first, then AT. */
  issue(arg: { accessData: TAccess; refreshData: TRefresh }): Promise<void>;
  /** Coordinated revoke: fires `onRevoke`, then clears both tokens. */
  revoke(): Promise<void>;
}

export interface H3TokenPairHooks<
  TAccess extends SessionData = SessionClaims,
  TRefresh extends SessionData = SessionClaims,
> {
  /**
   * Fires when the access token session is successfully read and validated.
   * Use for logging, metrics, or early revocation checks.
   */
  onReadAccess?(args: {
    access: SessionSnapshot<TAccess>;
    refresh: SessionSnapshot<TRefresh>;
    event: H3Event;
  }): void | Promise<void>;

  /**
   * Fires when the refresh token session is successfully read and validated.
   * Use for logging, metrics, or early revocation checks.
   */
  onReadRefresh?(args: {
    refresh: SessionSnapshot<TRefresh>;
    event: H3Event;
  }): void | Promise<void>;

  /**
   * Fires when the access token is expired or missing and a valid
   * refresh token exists. Call `issue(accessData)` to re-issue the
   * access token and rotate the refresh token. Call `revoke()` to
   * clear both tokens (e.g., user banned, family revoked). If neither
   * is called, the access token stays empty and the refresh token
   * is preserved. Throwing forwards to `onError` without destroying
   * any tokens.
   */
  onRefresh(args: {
    refresh: TokenPairSessionManager<TRefresh>;
    event: H3Event;
    /** Re-issue the access token with the given data and rotate the refresh token. */
    issue(arg: {
      accessData: SessionUpdate<TAccess>;
      refreshData?: SessionUpdate<TRefresh>;
    }): Promise<void>;
    /** Clear both tokens (e.g., user banned, family revoked). */
    revoke(): Promise<void>;
  }): void | Promise<void>;

  /**
   * Fires after a successful refresh cycle. Both snapshots reflect
   * the NEW state after rotation. Use for audit logging, jti tracking,
   * or external store sync.
   */
  onAfterRefresh?(args: {
    access: SessionSnapshot<TAccess>;
    refresh: SessionSnapshot<TRefresh>;
    previousRefresh: SessionSnapshot<TRefresh>;
    event: H3Event;
  }): void | Promise<void>;

  /**
   * Fires on revoke (via `tokenPair.revoke()`), before clearing.
   * Sessions reflect pre-clear state. Use to mark token ids as
   * revoked in external storage.
   */
  onRevoke?(args: {
    access: TokenPairSessionManager<TAccess>;
    refresh: TokenPairSessionManager<TRefresh>;
    event: H3Event;
  }): void | Promise<void>;

  /**
   * Fires on any non-expiry error during token pair operations.
   */
  onError?(args: {
    error: unknown;
    source: "access" | "refresh";
    event: H3Event;
  }): void | Promise<void>;
}

/**
 * Options for {@link defineTokenPair}.
 *
 * Both `access.maxAge` and `refresh.maxAge` are required — there is no
 * sensible default for token lifetimes. A runtime error is thrown if
 * either is missing (belt and suspenders for JS consumers).
 */
export interface H3TokenPairOptions<TAccess extends SessionData, TRefresh extends SessionData> {
  access: {
    key: SessionConfigJWS<TAccess, ExpiresIn>["key"];
    maxAge: ExpiresIn;
    name?: string;
    cookie?: SessionConfigJWS<TAccess, ExpiresIn>["cookie"];
    jws?: SessionConfigJWS<TAccess, ExpiresIn>["jws"];
  };
  refresh: {
    key: SessionConfigJWE<TRefresh, ExpiresIn>["key"];
    maxAge: ExpiresIn;
    name?: string;
    cookie?: SessionConfigJWE<TRefresh, ExpiresIn>["cookie"];
    jwe?: SessionConfigJWE<TRefresh, ExpiresIn>["jwe"];
  };
  hooks: H3TokenPairHooks<TAccess, TRefresh>;
}

/** Return type of {@link defineTokenPair}. */
export type DefineTokenPairReturn<TAccess extends SessionData, TRefresh extends SessionData> = (
  event: H3Event,
) => Promise<TokenPair<TAccess, TRefresh>>;

/**
 * Creates a token pair composable with coordinated AT/RT lifecycle.
 *
 * The access token (JWS, client-readable) is short-lived. The refresh
 * token (JWE, encrypted) is long-lived. When the AT expires and a valid
 * RT exists, the `onRefresh` hook fires — call `issue()` to re-issue
 * the AT and rotate the RT.
 *
 * @example
 * ```ts
 * const useAuth = defineTokenPair<
 *   { sub: string; permissions: string[] },
 *   { sub: string; family: string }
 * >({
 *   access: { key: atKeys, maxAge: "15m" },
 *   refresh: { key: rtKey, maxAge: "30D" },
 *   hooks: {
 *     async onRefresh({ refresh, issue }) {
 *       const user = await db.users.findById(refresh.data.sub);
 *       if (!user || user.suspended) return;
 *       await issue({ sub: user.id, permissions: user.permissions });
 *     },
 *   },
 * });
 * ```
 *
 * @throws {Error} If `access.maxAge` or `refresh.maxAge` is missing.
 */
export function defineTokenPair<TAccess extends SessionData, TRefresh extends SessionData>(
  options: H3TokenPairOptions<TAccess, TRefresh>,
): DefineTokenPairReturn<TAccess, TRefresh> {
  if (!options.access.maxAge) {
    throw new Error("[unauth] access.maxAge is required for defineTokenPair");
  }
  if (!options.refresh.maxAge) {
    throw new Error("[unauth] refresh.maxAge is required for defineTokenPair");
  }

  const rtConfig = {
    key: options.refresh.key,
    maxAge: options.refresh.maxAge,
    name: options.refresh.name ?? DEFAULT_RT_NAME,
    cookie: {
      ...DEFAULT_SECURE_COOKIE,
      ...options.refresh.cookie,
    } as const,
    jwe: options.refresh.jwe,
    hooks: {
      async onRead({ session, event }) {
        if (session.id) {
          await options.hooks.onReadRefresh?.({
            refresh: { ...session, id: session.id },
            event: event as H3Event,
          });
        }
      },
    },
  } satisfies SessionConfigJWE<TRefresh, ExpiresIn>;

  const atConfig = {
    key: options.access.key,
    maxAge: options.access.maxAge,
    name: options.access.name ?? DEFAULT_AT_NAME,
    cookie: {
      ...DEFAULT_AT_COOKIE,
      ...options.access.cookie,
    } as const,
    jws: options.access.jws,
    hooks: {
      async onRead({ session, event }) {
        if (session.id && options.hooks.onReadAccess) {
          const refresh = await getJWESession<TRefresh, ExpiresIn>(event, {
            ...rtConfig,
            hooks: undefined,
          });
          await options.hooks.onReadAccess({
            access: { ...session, id: session.id },
            refresh: { ...refresh, id: refresh.id! },
            event: event as H3Event,
          });
        }
      },
    },
  } satisfies SessionConfigJWS<TAccess, ExpiresIn>;

  return async (event: H3Event): Promise<TokenPair<TAccess, TRefresh>> => {
    const access = await useJWSSession<TAccess, ExpiresIn>(event, atConfig);
    const refresh = await useJWESession<TRefresh, ExpiresIn>(event, rtConfig);

    // Auto-refresh: AT is absent (missing cookie or expired JWT) but RT is valid.
    // Handles both cases uniformly — the browser deletes AT cookies when Max-Age
    // elapses, so by the time a request arrives the AT cookie may simply be gone.
    if (!access.id && refresh.id) {
      const previousRefresh = { ...refresh, id: refresh.id };

      let issued = false;
      let revoked = false;
      let issuedAccess: SessionSnapshot<TAccess> | undefined;

      const issue = async (arg: {
        accessData: SessionUpdate<TAccess>;
        refreshData?: SessionUpdate<TRefresh>;
      }): Promise<void> => {
        const at = await updateJWSSession<TAccess, ExpiresIn>(event, atConfig, arg.accessData);
        await refresh.update(arg.refreshData);
        issuedAccess = { ...at, id: at.id! };
        issued = true;
      };

      const revoke = async (): Promise<void> => {
        await refresh.clear();
        revoked = true;
      };

      try {
        await options.hooks.onRefresh({ refresh, event, issue, revoke });
      } catch (err) {
        await options.hooks.onError?.({ error: err, source: "access", event });
      }

      if (!revoked && issued && issuedAccess) {
        await options.hooks.onAfterRefresh?.({
          access: issuedAccess,
          refresh: { ...refresh, id: refresh.id! },
          previousRefresh,
          event,
        });
      }
    }

    return {
      get access() {
        return access;
      },
      get refresh() {
        return refresh;
      },
      async issue(arg: { accessData: TAccess; refreshData: TRefresh }): Promise<void> {
        await refresh.update(arg.refreshData);
        await access.update(arg.accessData);
      },
      async revoke(): Promise<void> {
        await options.hooks.onRevoke?.({
          access: access,
          refresh: refresh,
          event,
        });
        await access.clear();
        await refresh.clear();
      },
    };
  };
}

/** Configuration for {@link requireAuth} and {@link optionalAuth}. */
export interface TokenPairMiddlewareConfig<TAccess extends SessionData> {
  /**
   * Called after successful authentication, before the route handler.
   * Use for authorization checks (roles, permissions, etc.).
   * Throw to block the request.
   */
  onAuthenticated?(ctx: {
    session: TokenPairSessionManager<TAccess>;
    event: H3Event;
  }): void | Promise<void>;
}

/**
 * Middleware that requires a valid access token.
 * Throws `createError` with status 401 if no valid access token exists.
 *
 * @example
 * ```ts
 * app.use("/me", defineEventHandler({ onRequest: requireAuth(useAuth), handler }));
 * ```
 */
export function requireAuth<TAccess extends SessionData, TRefresh extends SessionData>(
  useAuth: DefineTokenPairReturn<TAccess, TRefresh>,
  config?: TokenPairMiddlewareConfig<TAccess>,
): (event: H3Event) => Promise<void> {
  return async (event: H3Event): Promise<void> => {
    const { access } = await useAuth(event);
    if (!access.id) {
      throw createError({ statusCode: 401, statusMessage: "Unauthorized" });
    }
    await config?.onAuthenticated?.({ session: access, event });
  };
}

/**
 * Middleware that allows unauthenticated requests.
 * Resolves the token pair but does not throw if the access token is absent.
 * `onAuthenticated` only fires when a valid access token exists.
 *
 * @example
 * ```ts
 * app.use("/feed", defineEventHandler({ onRequest: optionalAuth(useAuth), handler }));
 * ```
 */
export function optionalAuth<TAccess extends SessionData, TRefresh extends SessionData>(
  useAuth: DefineTokenPairReturn<TAccess, TRefresh>,
  config?: TokenPairMiddlewareConfig<TAccess>,
): (event: H3Event) => Promise<void> {
  return async (event: H3Event): Promise<void> => {
    const { access } = await useAuth(event);
    if (access.id) {
      await config?.onAuthenticated?.({ session: access, event });
    }
  };
}
