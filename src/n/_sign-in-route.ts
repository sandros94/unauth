import type { SessionConfigJWE } from "unjwt/session";
import { UnauthError, isUnauthError } from "../_internal/error.ts";
import { HANDOFF_PARAM, type HandoffCarrier, handoffCarrier } from "./_handoff.ts";
import { type StartFlowOptions, startFlow } from "./flow/start-flow.ts";
import { type FlowResult, completeFlow } from "./flow/complete-flow.ts";
import type { Provider } from "./flow/types.ts";
import { type FlowIntent, type WebRequestEvent, isCallback } from "./request-event.ts";

/** What {@link signInRoute} serves: the flow, its key, and the route's steps for each request. */
export interface SignInRoute<TProfile, TResult, TEvent extends WebRequestEvent, TLink> {
  /** Every option of both legs but the flow key and the request's intent. */
  flow: Omit<StartFlowOptions, keyof FlowIntent | "key" | "context">;
  /** The flow key, asked for on every request. */
  key: () => Promise<SessionConfigJWE["key"]>;
  /** The steps of one request, asked for once at its start. */
  steps: (event: TEvent) => SignInSteps<TProfile, TResult, TLink>;
}

/** The steps of one request around the flow. */
export interface SignInSteps<TProfile, TResult, TLink> {
  onStart?: () => FlowIntent<TLink> | void | Promise<FlowIntent<TLink> | void>;
  onError?: (error: UnauthError) => TResult | Response | Promise<TResult | Response>;
  /** Turns a completed sign-in into the response. */
  complete: (result: FlowResult<TProfile, TLink>) => Promise<TResult | Response>;
}

/**
 * One route for both legs of a sign-in: without `code`/`error` (or a `form_post` body) it answers
 * the redirect to the provider, otherwise it completes the callback and returns `complete`'s
 * value. A result whose `returnHost` is another host is redirected there in a sealed, single-use
 * handoff token, and `complete` runs on that host. The consumed flow cookie is expired on the
 * response, error responses included; an `UnauthError` is answered by `onError`, else by a plain
 * response.
 */
export function signInRoute<TProfile, TResult, TEvent extends WebRequestEvent, TLink>(
  provider: Provider<TProfile>,
  route: SignInRoute<TProfile, TResult, TEvent, TLink>,
): (event: TEvent) => Promise<TResult | Response> {
  const { flow } = route;
  let carrier:
    | { key: SessionConfigJWE["key"]; handoff: HandoffCarrier<TProfile, TLink> }
    | undefined;
  return async (event) => {
    const { onStart, onError, complete } = route.steps(event);
    const fail = async (error: UnauthError, headers?: Headers): Promise<TResult | Response> =>
      onError ? onError(error) : failureResponse(error, headers);

    let key: SessionConfigJWE["key"];
    try {
      key = await route.key();
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      return fail(error);
    }
    if (carrier?.key !== key) carrier = { key, handoff: handoffCarrier<TProfile, TLink>(key) };
    const { handoff } = carrier;

    const handed =
      provider.kind === "custom" ? new URL(event.req.url).searchParams.get(HANDOFF_PARAM) : null;
    if (handed !== null) {
      let result: FlowResult<TProfile, TLink>;
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
      return complete(result);
    }

    if (!isCallback(provider, event.req)) {
      try {
        const intent: FlowIntent<TLink> = (await onStart?.()) ?? {};
        return await startFlow<TLink>(provider, event.req, {
          ...flow,
          key,
          context: event.context,
          ...intent,
        });
      } catch (error) {
        if (!isUnauthError(error)) throw error;
        return fail(error);
      }
    }

    const headers = new Headers();
    let result: FlowResult<TProfile, TLink>;
    try {
      result = await completeFlow<TProfile, TLink>(provider, event.req, {
        ...flow,
        key,
        headers,
        context: event.context,
      });
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      if (!onError) return failureResponse(error, headers);
      copySetCookie(headers, event.res.headers);
      return onError(error);
    }
    copySetCookie(headers, event.res.headers);
    const here = new URL(event.req.url);
    if (result.returnHost !== undefined && result.returnHost !== here.hostname) {
      const target = new URL(here);
      target.hostname = result.returnHost;
      target.search = `?${HANDOFF_PARAM}=${encodeURIComponent(await handoff.issue(result))}`;
      return new Response(null, {
        status: 302,
        headers: { "location": target.href, "cache-control": "no-store" },
      });
    }
    return complete(result);
  };
}

/** A plain response for an `UnauthError`: its status (500 when it has none) and, below 500, its message; a 5xx carries a generic body. */
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
