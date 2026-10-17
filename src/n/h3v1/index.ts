import {
  type EventHandler,
  type H3Event,
  appendResponseHeader,
  createError,
  defineEventHandler,
  sendWebResponse,
  toWebRequest,
} from "h3";
import {
  type ExpiresIn,
  type SessionConfigJWE,
  type SessionConfigJWS,
  defineJWESession,
  defineJWSSession,
} from "unjwt/adapters/h3v1";
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

/** {@link defineAuthSession} config over h3 v1's JWE session; hooks receive `event`. */
export type H3AuthSessionConfig<TData extends AuthSessionRecord> = AuthSessionConfigOf<
  TData,
  SessionConfigJWE<AuthSessionData<TData>, ExpiresIn, H3Event>,
  { event: H3Event }
>;

/** {@link defineAuthSession} config over h3 v1's JWS session. */
export type H3AuthSessionConfigJWS<TData extends AuthSessionRecord> = AuthSessionConfigOf<
  TData,
  SessionConfigJWS<AuthSessionData<TData>, ExpiresIn, H3Event>,
  { event: H3Event }
>;

/** `unauth/n`'s auth session over h3 v1 events: JWE by default, JWS with `{ family: "jws" }`. */
export function defineAuthSession<TData extends AuthSessionRecord>(
  config: H3AuthSessionConfig<TData>,
  options?: { family?: "jwe" },
): AuthSessionDefinition<TData, H3Event>;
export function defineAuthSession<TData extends AuthSessionRecord>(
  config: H3AuthSessionConfigJWS<TData>,
  options: { family: "jws" },
): AuthSessionDefinition<TData, H3Event>;
export function defineAuthSession<TData extends AuthSessionRecord>(
  config: H3AuthSessionConfig<TData> | H3AuthSessionConfigJWS<TData>,
  options?: { family?: "jwe" | "jws" },
): AuthSessionDefinition<TData, H3Event> {
  const define = options?.family === "jws" ? defineJWSSession : defineJWESession;
  return composeAuthSession<TData, H3Event>(config, { define });
}

/**
 * One route for both legs of a sign-in: without `code`/`error` (or a `form_post` body) it
 * redirects to the provider, otherwise it completes the callback and returns `onSuccess`'s
 * value. The consumed flow cookie is expired on the response, error responses included.
 */
export function defineOAuthEventHandler<TProfile, TResult>(
  provider: Provider<TProfile>,
  options: OAuthEventHandlerOptions<H3Event, TProfile, TResult>,
): EventHandler {
  const { onAuthorize, onSuccess, onError, ...flow } = options;
  return defineEventHandler(async (event) => {
    const handle = {
      onError: onError && ((error: UnauthError) => onError(event, error)),
      toHttpError,
    };
    const request = toWebRequest(event);
    if (!isCallbackLeg(provider, request)) {
      const intent = (await onAuthorize?.(event)) ?? {};
      const step = await runFlow(
        () => authorize(provider, request, { ...flow, ...intent }),
        handle,
      );
      return step.ok ? sendWebResponse(event, step.value) : step.value;
    }
    const headers = new Headers();
    const step = await runFlow(async () => {
      try {
        return await callback(provider, request, { ...flow, headers });
      } finally {
        for (const line of headers.getSetCookie()) appendResponseHeader(event, "set-cookie", line);
      }
    }, handle);
    return step.ok ? onSuccess(event, step.value) : step.value;
  });
}

/** Configuration of {@link requireSession} and {@link optionalSession}. */
export interface SessionMiddlewareConfig<TData extends AuthSessionRecord> {
  /** Runs for an authenticated session, before the handler; throw to refuse the request. */
  onAuthenticated?: (context: {
    session: AuthSessionManager<TData>;
    event: H3Event;
  }) => void | Promise<void>;
}

/** `onRequest` hook answering `401` unless the request carries an authenticated session. */
export function requireSession<TData extends AuthSessionRecord>(
  definition: AuthSessionDefinition<TData, H3Event>,
  config?: SessionMiddlewareConfig<TData>,
): (event: H3Event) => Promise<void> {
  return async (event) => {
    const session = await definition.use(event);
    try {
      authenticatedOrThrow(session);
    } catch (error) {
      throw createError({ statusCode: 401, statusMessage: "Unauthorized", cause: error });
    }
    await config?.onAuthenticated?.({ session, event });
  };
}

/** `onRequest` hook resolving the session without requiring it; `onAuthenticated` runs only with one. */
export function optionalSession<TData extends AuthSessionRecord>(
  definition: AuthSessionDefinition<TData, H3Event>,
  config?: SessionMiddlewareConfig<TData>,
): (event: H3Event) => Promise<void> {
  return async (event) => {
    const session = await definition.use(event);
    if (authenticatedOrUndefined(session)) await config?.onAuthenticated?.({ session, event });
  };
}

function toHttpError(error: UnauthError): Error {
  const { status, message } = httpErrorOf(error);
  return createError({ statusCode: status, message, cause: error });
}
