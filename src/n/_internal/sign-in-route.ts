import type { SessionConfigJWE } from "unjwt/session";
import { UnauthError, isUnauthError } from "../../error.ts";
import {
  HANDOFF_PARAM,
  type HandoffCarrier,
  handoffCarrier,
} from "../flow/_internal/carrier/handoff.ts";
import { type StartFlowOptions, startFlow } from "../flow/start-flow.ts";
import type { FlowResult } from "../flow/types.ts";
import { type CompletedFlow, completeFlowWithReturnHost } from "../flow/_internal/complete.ts";
import type { Provider } from "../flow/types.ts";
import { type FlowIntent, type WebRequestEvent, isCallback } from "../request-event.ts";

/** What {@link signInRoute} serves: the flow, its key, and the route's steps for each request. */
export interface SignInRoute<TProfile, TResult, TEvent extends WebRequestEvent, TMemo> {
  /** Every option of both legs but the flow key and the request's intent. */
  flow: Omit<StartFlowOptions, keyof FlowIntent | "key" | "context">;
  /** The flow key, asked for on every request. */
  key: () => Promise<SessionConfigJWE["key"]>;
  /** The steps of one request, asked for once at its start. */
  steps: (event: TEvent) => SignInSteps<TProfile, TResult, TMemo>;
}

/** The steps of one request around the flow. */
export interface SignInSteps<TProfile, TResult, TMemo> {
  onStart?: () => FlowIntent<TMemo> | void | Promise<FlowIntent<TMemo> | void>;
  onError?: (error: UnauthError) => TResult | Response | Promise<TResult | Response>;
  /** Turns a completed sign-in into the response. */
  complete: (result: FlowResult<TProfile, TMemo>) => Promise<TResult | Response>;
}

/**
 * One route for both legs of a sign-in, answering `GET` and `POST` and refusing any other method
 * with a `405`, so it is mounted without a method filter: without `code`/`error` (or a
 * `form_post` body) it answers the redirect to the provider, otherwise it completes the callback
 * and returns `complete`'s value. A sign-in a relocation moved off its starting host is redirected back there with the
 * result in a sealed, single-use handoff token, and `complete` runs on that host. The consumed flow cookie is expired on the
 * response, error responses included; an `UnauthError` is answered by `onError`, else by a plain
 * response.
 */
export function signInRoute<TProfile, TResult, TEvent extends WebRequestEvent, TMemo>(
  provider: Provider<TProfile>,
  route: SignInRoute<TProfile, TResult, TEvent, TMemo>,
): (event: TEvent) => Promise<TResult | Response> {
  const { flow } = route;
  let carrier:
    | { key: SessionConfigJWE["key"]; handoff: HandoffCarrier<TProfile, TMemo> }
    | undefined;
  return async (event) => {
    const { method } = event.req;
    if (method !== "GET" && method !== "POST") {
      return new Response(null, { status: 405, headers: { allow: "GET, POST" } });
    }
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
    if (carrier?.key !== key) carrier = { key, handoff: handoffCarrier<TProfile, TMemo>(key) };
    const { handoff } = carrier;

    const handed =
      provider.kind === "custom" ? new URL(event.req.url).searchParams.get(HANDOFF_PARAM) : null;
    if (handed !== null) {
      let result: FlowResult<TProfile, TMemo>;
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
        const intent: FlowIntent<TMemo> = (await onStart?.()) ?? {};
        return await startFlow<TMemo>(provider, event.req, {
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
    let completed: CompletedFlow<TProfile, TMemo>;
    try {
      completed = await completeFlowWithReturnHost<TProfile, TMemo>(provider, event.req, {
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
    const { result, returnHost } = completed;
    const here = new URL(event.req.url);
    if (returnHost !== undefined && returnHost !== here.hostname) {
      const target = new URL(here);
      target.hostname = returnHost;
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
