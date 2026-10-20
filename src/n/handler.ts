import type { SessionRequestEvent } from "unjwt/session";
import { type UnauthError, isUnauthError } from "../_internal/error.ts";
import { type StartFlowOptions, startFlow } from "./flow/start-flow.ts";
import { type FlowResult, completeFlow } from "./flow/complete-flow.ts";
import type { Provider } from "./flow/types.ts";
import type {
  AuthSessionDefinition,
  AuthSessionRecord,
  AuthenticatedSessionManager,
} from "./session.ts";

/**
 * A request event a handler answers: the web-standard `{ req, res, context }` that h3 v2, Nitro 3
 * and a `nuxt/server` handler receive, with the `res` the response is sent with.
 */
export interface HandlerEvent extends SessionRequestEvent {
  readonly res: { readonly headers: Headers };
}

/** What a request may add to the authorization leg: where to return, which user links, extra scopes. */
export type FlowIntent = Pick<StartFlowOptions, "redirect" | "link" | "scopes" | "params">;

/** Options of {@link defineSignInHandler}. */
export interface SignInHandlerConfig<
  TProfile = unknown,
  TResult = unknown,
  TEvent extends HandlerEvent = HandlerEvent,
> extends Omit<StartFlowOptions, keyof FlowIntent> {
  /** Per-request additions to the authorization leg. */
  onStart?: (event: TEvent) => FlowIntent | void | Promise<FlowIntent | void>;
  /** Runs after a completed callback; its return value is the response. */
  onSuccess: (event: TEvent, result: FlowResult<TProfile>) => TResult | Promise<TResult>;
  /**
   * Answers a failed flow; its return value is the response. Without it the failure is answered
   * with a plain `Response` carrying the error's status: its message for a 4xx, nothing for a 5xx.
   */
  onError?: (event: TEvent, error: UnauthError) => TResult | Response | Promise<TResult | Response>;
}

/**
 * One route for both legs of a sign-in: without `code`/`error` (or a `form_post` body) it answers
 * the redirect to the provider, otherwise it completes the callback and returns `onSuccess`'s
 * value. The consumed flow cookie is expired on the response, error responses included.
 *
 * The handler takes the event as it is on h3 v2, Nitro 3 and `nuxt/server`, and returns either a
 * `Response` (the redirect, or a failure without `onError`) or what `onSuccess` / `onError`
 * return. Narrow `TEvent` by annotating `onSuccess`'s event.
 */
export function defineSignInHandler<TProfile, TResult, TEvent extends HandlerEvent = HandlerEvent>(
  provider: Provider<TProfile>,
  options: SignInHandlerConfig<TProfile, TResult, TEvent>,
): (event: TEvent) => Promise<TResult | Response> {
  const { onStart, onSuccess, onError, ...flow } = options;
  return async (event) => {
    const fail = (error: UnauthError, headers?: Headers) =>
      onError ? onError(event, error) : failureResponse(error, headers);

    if (!isCallback(provider, event.req)) {
      try {
        const intent = (await onStart?.(event)) ?? {};
        return await startFlow(provider, event.req, { ...flow, ...intent });
      } catch (error) {
        if (!isUnauthError(error)) throw error;
        return fail(error);
      }
    }

    const headers = new Headers();
    let result: FlowResult<TProfile>;
    try {
      result = await completeFlow(provider, event.req, { ...flow, headers });
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      if (!onError) return failureResponse(error, headers);
      copySetCookie(headers, event.res.headers);
      return onError(event, error);
    }
    copySetCookie(headers, event.res.headers);
    return onSuccess(event, result);
  };
}

/** Configuration of {@link defineSessionGuard}. */
export interface AuthSessionGuardConfig<TData extends AuthSessionRecord, TContext> {
  /** Runs for an authenticated session, before the handler; throw to refuse the request. */
  onAuthenticated?: (args: {
    session: AuthenticatedSessionManager<TData>;
    context: TContext;
  }) => void | Promise<void>;
}

/**
 * Middleware answering `401` unless the request carries an authenticated session: it returns a
 * `Response` to end the request, and nothing to let it through, as h3 v2, Nitro 3 and a
 * `nuxt/server` middleware expect. The handler behind it reads the same session with `require()`.
 */
export function defineSessionGuard<TData extends AuthSessionRecord, TContext>(
  definition: AuthSessionDefinition<TData, TContext>,
  config?: AuthSessionGuardConfig<TData, TContext>,
): (context: TContext) => Promise<Response | undefined> {
  return async (context) => {
    let session: AuthenticatedSessionManager<TData>;
    try {
      session = await definition.require(context);
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      return failureResponse(error);
    }
    await config?.onAuthenticated?.({ session, context });
    return undefined;
  };
}

/** Whether a request to the single OAuth route is the provider's redirect back (the callback leg). */
export function isCallback(
  provider: Provider<unknown>,
  request: { url: string; method: string },
): boolean {
  const query = new URL(request.url).searchParams;
  if (query.has("code") || query.has("error")) return true;
  return provider.responseMode === "form_post" && request.method === "POST";
}

/** A plain response for an `UnauthError`: its status and, below 500, its message; 5xx details stay in `cause`. */
function failureResponse(error: UnauthError, headers?: Headers): Response {
  const status = error.status ?? 500;
  return new Response(status >= 500 ? "Sign-in is unavailable." : error.message, {
    status,
    headers: new Headers(headers),
  });
}

function copySetCookie(from: Headers, to: Headers): void {
  for (const line of from.getSetCookie()) to.append("set-cookie", line);
}
