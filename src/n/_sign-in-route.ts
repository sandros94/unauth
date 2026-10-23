import type { SessionConfigJWE } from "unjwt/session";
import { UnauthError, isUnauthError } from "../_internal/error.ts";
import { HANDOFF_PARAM, type HandoffCarrier, handoffCarrier } from "./_handoff.ts";
import { type StartFlowOptions, startFlow } from "./flow/start-flow.ts";
import { type FlowResult, completeFlow } from "./flow/complete-flow.ts";
import type { Provider } from "./flow/types.ts";
import { type FlowIntent, type HandlerEvent, isCallback } from "./handler.ts";

/** What {@link signInRoute} serves: the flow, its key, and the route's steps around it. */
export interface SignInRoute<TProfile, TResult, TEvent extends HandlerEvent> {
  /** Every option of both legs but the flow key and the request's intent. */
  flow: Omit<StartFlowOptions, keyof FlowIntent | "key">;
  /** The flow key, asked for on every request. */
  key: () => Promise<SessionConfigJWE["key"]>;
  onStart?: (event: TEvent) => FlowIntent | void | Promise<FlowIntent | void>;
  onError?: (event: TEvent, error: UnauthError) => TResult | Response | Promise<TResult | Response>;
  /** Turns a completed sign-in into the response; `fail` answers a refusal as a failed flow is. */
  complete: (
    event: TEvent,
    result: FlowResult<TProfile>,
    fail: (error: UnauthError) => Promise<TResult | Response>,
  ) => Promise<TResult | Response>;
}

/**
 * One route for both legs of a sign-in: without `code`/`error` (or a `form_post` body) it answers
 * the redirect to the provider, otherwise it completes the callback and returns `complete`'s
 * value, on the host the user started on. The consumed flow cookie is expired on the response,
 * error responses included; an `UnauthError` is answered by `onError`, else by a plain response.
 */
export function signInRoute<TProfile, TResult, TEvent extends HandlerEvent>(
  provider: Provider<TProfile>,
  route: SignInRoute<TProfile, TResult, TEvent>,
): (event: TEvent) => Promise<TResult | Response> {
  const { flow, onStart, onError, complete } = route;
  let carrier: { key: SessionConfigJWE["key"]; handoff: HandoffCarrier<TProfile> } | undefined;
  return async (event) => {
    const fail = async (error: UnauthError, headers?: Headers): Promise<TResult | Response> =>
      onError ? onError(event, error) : failureResponse(error, headers);

    let key: SessionConfigJWE["key"];
    try {
      key = await route.key();
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      return fail(error);
    }
    if (carrier?.key !== key) carrier = { key, handoff: handoffCarrier(key) };
    const { handoff } = carrier;

    const handed = new URL(event.req.url).searchParams.get(HANDOFF_PARAM);
    if (handed !== null) {
      let result: FlowResult<TProfile>;
      try {
        result = await handoff.take(handed);
      } catch (error) {
        return fail(
          new UnauthError(
            "[unauth/n] The sign-in handed over to this host is invalid, expired or already used.",
            "ERR_AUTHN_FLOW_EXPIRED",
            { status: 401, cause: { reason: "consumed", error } },
          ),
        );
      }
      return complete(event, result, fail);
    }

    if (!isCallback(provider, event.req)) {
      try {
        const intent = (await onStart?.(event)) ?? {};
        return await startFlow(provider, event.req, { ...flow, key, ...intent });
      } catch (error) {
        if (!isUnauthError(error)) throw error;
        return fail(error);
      }
    }

    const headers = new Headers();
    let result: FlowResult<TProfile>;
    try {
      result = await completeFlow(provider, event.req, { ...flow, key, headers });
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      if (!onError) return failureResponse(error, headers);
      copySetCookie(headers, event.res.headers);
      return onError(event, error);
    }
    copySetCookie(headers, event.res.headers);
    const here = new URL(event.req.url);
    if (result.returnHost !== undefined && result.returnHost !== here.hostname) {
      // The user started on another host (a `devHosts` relocation): the result travels there in
      // a sealed, short-lived, single-use token, and the sign-in completes where the session lives.
      const target = new URL(here);
      target.hostname = result.returnHost;
      target.search = `?${HANDOFF_PARAM}=${encodeURIComponent(await handoff.issue(result))}`;
      return new Response(null, {
        status: 302,
        headers: { "location": target.href, "cache-control": "no-store" },
      });
    }
    return complete(event, result, fail);
  };
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
