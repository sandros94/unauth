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

export {
  type JWK,
  type JWK_oct,
  type JWK_RSA,
  type JWK_EC,
  type JWK_OKP,
  generateJWK,
  importJWKFromPEM,
  exportJWKToPEM,
  deriveJWKFromPassword,
} from "unjwt/adapters/h3v2";

export interface H3SessionHooks<
  T extends Record<string, any> = SessionClaims,
  MaxAge extends ExpiresIn | undefined = ExpiresIn | undefined,
> extends Omit<SessionHooksJWE<T, MaxAge>, "onRead"> {
  onRead?(args: {
    session: SessionJWE<T, MaxAge>;
    event: HTTPEvent;
    config: SessionConfigJWE<T, MaxAge>;
    clear(): Promise<void>;
  }): void | Promise<void>;

  onRefresh?(args: {
    session: SessionJWE<T, MaxAge>;
    event: HTTPEvent;
    config: SessionConfigJWE<T, MaxAge>;
    refresh(update?: SessionUpdate<T>): Promise<void>;
    clear(): Promise<void>;
  }): void | Promise<void>;
}

export interface H3SessionOptions<T extends SessionData> extends Omit<
  SessionConfigJWE<T>,
  "hooks"
> {
  refreshAfter?: number | false;
  hooks?: H3SessionHooks<T>;
}

export type SessionManager<T extends SessionData> = BaseSessionManager<T, ExpiresIn>;
export type DefineSessionReturn<T extends SessionData> = (
  event: HTTPEvent,
) => Promise<SessionManager<T>>;

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

export interface SessionMiddlewareConfig<T extends SessionData> {
  onAuthenticated?(ctx: { session: SessionManager<T>; event: HTTPEvent }): void | Promise<void>;
}

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
