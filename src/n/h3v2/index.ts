import { type H3Event, type HTTPEvent, HTTPError } from "h3";
import {
  type ExpiresIn,
  type SessionConfigJWE,
  type SessionConfigJWS,
  defineJWESession,
  defineJWSSession,
} from "unjwt/adapters/h3v2";
import type { UnauthError } from "../../_internal/error.ts";
import { type OAuthEventHandlerOptions, httpErrorOf, isCallbackLeg, runFlow } from "../_glue.ts";
import { composeAuthSession } from "../_session-define.ts";
import { authorize } from "../flow/authorize.ts";
import { callback } from "../flow/callback.ts";
import type { Provider } from "../flow/types.ts";
import {
  type AuthSessionConfigOf,
  type AuthSessionData,
  type AuthSessionDefinition,
  type AuthSessionManager,
  type AuthSessionRecord,
  optionalSession as authenticatedOrUndefined,
  requireSession as authenticatedOrThrow,
} from "../session.ts";

export type { AuthorizeIntent, OAuthEventHandlerOptions } from "../_glue.ts";

/** {@link defineAuthSession} config over h3 v2's JWE session; hooks receive `event`. */
export type H3AuthSessionConfig<TData extends AuthSessionRecord> = AuthSessionConfigOf<
  TData,
  SessionConfigJWE<AuthSessionData<TData>, ExpiresIn>,
  { event: HTTPEvent }
>;

/** {@link defineAuthSession} config over h3 v2's JWS session. */
export type H3AuthSessionConfigJWS<TData extends AuthSessionRecord> = AuthSessionConfigOf<
  TData,
  SessionConfigJWS<AuthSessionData<TData>, ExpiresIn>,
  { event: HTTPEvent }
>;

/** `unauth/n`'s auth session over h3 v2 events: JWE by default, JWS with `{ family: "jws" }`. */
export function defineAuthSession<TData extends AuthSessionRecord>(
  config: H3AuthSessionConfig<TData>,
  options?: { family?: "jwe" },
): AuthSessionDefinition<TData, HTTPEvent>;
export function defineAuthSession<TData extends AuthSessionRecord>(
  config: H3AuthSessionConfigJWS<TData>,
  options: { family: "jws" },
): AuthSessionDefinition<TData, HTTPEvent>;
export function defineAuthSession<TData extends AuthSessionRecord>(
  config: H3AuthSessionConfig<TData> | H3AuthSessionConfigJWS<TData>,
  options?: { family?: "jwe" | "jws" },
): AuthSessionDefinition<TData, HTTPEvent> {
  const define = options?.family === "jws" ? defineJWSSession : defineJWESession;
  return composeAuthSession<TData, HTTPEvent>(config, { define });
}

/**
 * One route for both legs of a sign-in: without `code`/`error` (or a `form_post` body) it
 * redirects to the provider, otherwise it completes the callback and returns `onSuccess`'s
 * value. The consumed flow cookie is expired on the response, error responses included.
 */
export function defineOAuthEventHandler<TProfile, TResult>(
  provider: Provider<TProfile>,
  options: OAuthEventHandlerOptions<H3Event, TProfile, TResult>,
): (event: H3Event) => Promise<unknown> {
  const { onAuthorize, onSuccess, onError, ...flow } = options;
  return async (event) => {
    const handle = {
      onError: onError && ((error: UnauthError) => onError(event, error)),
      toHttpError,
    };
    if (!isCallbackLeg(provider, event.req)) {
      const intent = (await onAuthorize?.(event)) ?? {};
      return (await runFlow(() => authorize(provider, event.req, { ...flow, ...intent }), handle))
        .value;
    }
    const headers = new Headers();
    const step = await runFlow(async () => {
      try {
        return await callback(provider, event.req, { ...flow, headers });
      } finally {
        for (const line of headers.getSetCookie()) {
          event.res.headers.append("set-cookie", line);
          event.res.errHeaders.append("set-cookie", line);
        }
      }
    }, handle);
    return step.ok ? onSuccess(event, step.value) : step.value;
  };
}

/** Configuration of {@link requireSession} and {@link optionalSession}. */
export interface SessionMiddlewareConfig<TData extends AuthSessionRecord> {
  /** Runs for an authenticated session, before the handler; throw to refuse the request. */
  onAuthenticated?: (context: {
    session: AuthSessionManager<TData>;
    event: HTTPEvent;
  }) => void | Promise<void>;
}

/** Middleware answering `401` unless the request carries an authenticated session. */
export function requireSession<TData extends AuthSessionRecord>(
  definition: AuthSessionDefinition<TData, HTTPEvent>,
  config?: SessionMiddlewareConfig<TData>,
): (event: HTTPEvent) => Promise<void> {
  return async (event) => {
    const session = await definition.use(event);
    try {
      authenticatedOrThrow(session);
    } catch (error) {
      throw new HTTPError({ status: 401, message: "Unauthorized", cause: error });
    }
    await config?.onAuthenticated?.({ session, event });
  };
}

/** Middleware resolving the session without requiring it; `onAuthenticated` runs only with one. */
export function optionalSession<TData extends AuthSessionRecord>(
  definition: AuthSessionDefinition<TData, HTTPEvent>,
  config?: SessionMiddlewareConfig<TData>,
): (event: HTTPEvent) => Promise<void> {
  return async (event) => {
    const session = await definition.use(event);
    if (authenticatedOrUndefined(session)) await config?.onAuthenticated?.({ session, event });
  };
}

function toHttpError(error: UnauthError): HTTPError {
  return new HTTPError({ ...httpErrorOf(error), cause: error });
}
