import type { FlowKey } from "./flow-key.ts";
import type { UnauthError } from "../../error.ts";
import { isUnauthError } from "../../error.ts";
import {
  HANDOFF_PARAM,
  type Handoff,
  type HandoffCarrier,
  type RelocatedFailure,
  handoffCarrier,
  handoffFailure,
  redeemHandoff,
} from "../flow/_internal/carrier/handoff.ts";
import { carriesIntent, definedIntent } from "../flow/_internal/carrier/intent.ts";
import type { StartFlowOptions } from "../flow/start-flow.ts";
import { startFlowWithReturnHost } from "../flow/_internal/start.ts";
import type { FlowResult } from "../flow/types.ts";
import { type CompletedFlow, completeFlowWithReturnHost } from "../flow/_internal/complete.ts";
import type { Provider } from "../flow/types.ts";
import { type FlowIntent, type WebRequestEvent, isCallback } from "../request-event.ts";

/** What {@link signInRoute} serves: the flow, its key, and the route's steps for each request. */
export interface SignInRoute<TProfile, TResult, TEvent extends WebRequestEvent, TMemo> {
  /** Every option of both legs but the flow key and the request's intent. */
  flow: Omit<StartFlowOptions, keyof FlowIntent | "key" | "context">;
  /** The flow key, asked for on every request. */
  key: () => Promise<FlowKey>;
  /** The steps of one request, asked for once at its start. */
  steps: (event: TEvent) => SignInSteps<TProfile, TResult, TMemo>;
}

/** The steps of one request around the flow. */
export interface SignInSteps<TProfile, TResult, TMemo> {
  onStart?: () => FlowIntent<TMemo> | void | Promise<FlowIntent<TMemo> | void>;
  onError?: (error: UnauthError) => TResult | Response | void | Promise<TResult | Response | void>;
  /** Turns a completed sign-in into the response. */
  complete: (result: FlowResult<TProfile, TMemo>) => Promise<TResult | Response>;
}

/**
 * One route for both legs of a sign-in, answering `GET` and `POST` and refusing any other method
 * with a `405`, so it is mounted without a method filter: a request that is not the callback leg
 * (see `isCallback`) answers the redirect to the provider, otherwise it completes the callback
 * and returns `complete`'s value. A sign-in a relocation moved off its starting host is redirected
 * back there with the result, or its `UnauthError`, in a sealed, single-use handoff token; that
 * host redeems it against the flow it recorded when the sign-in left, in the browser that started
 * it, and `complete` or `onError` runs there; `onStart` ran there too and is not called on the
 * relocated start. The consumed flow cookie is expired on the response, error responses included (on the
 * event's `errHeaders` too, for a framework that keeps those apart); an `UnauthError`, the flow's
 * or one `onStart` or `complete` throws, is answered by `onError`, else (or when it answers
 * nothing) by a plain response.
 */
export function signInRoute<TProfile, TResult, TEvent extends WebRequestEvent, TMemo>(
  provider: Provider<TProfile>,
  route: SignInRoute<TProfile, TResult, TEvent, TMemo>,
): (event: TEvent) => Promise<TResult | Response> {
  const { flow } = route;
  let carrier: { key: FlowKey; handoff: HandoffCarrier<TProfile, TMemo> } | undefined;
  return async (event) => {
    const { method } = event.req;
    if (method !== "GET" && method !== "POST") {
      return new Response(null, { status: 405, headers: { allow: "GET, POST" } });
    }
    const { onStart, onError, complete } = route.steps(event);
    const fail = async (error: UnauthError, headers?: Headers): Promise<TResult | Response> => {
      if (!onError) return failureResponse(error, headers);
      if (headers) copySetCookie(headers, event.res);
      const answer = await onError(error);
      return answer === undefined ? failureResponse(error) : answer;
    };

    let key: FlowKey;
    let handoff: HandoffCarrier<TProfile, TMemo>;
    try {
      key = await route.key();
      if (carrier?.key !== key) {
        carrier = {
          key,
          handoff: handoffCarrier<TProfile, TMemo>(key, {
            jwe: flow.jwe,
            onKeyLookup: flow.onKeyLookup,
          }),
        };
      }
      handoff = carrier.handoff;
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      return fail(error);
    }

    const handed =
      provider.kind === "custom" ? new URL(event.req.url).searchParams.get(HANDOFF_PARAM) : null;
    if (handed !== null) {
      const headers = new Headers();
      let result: FlowResult<TProfile, TMemo>;
      try {
        result = await redeemHandoff<TProfile, TMemo>(provider, event.req, {
          token: handed,
          carrier: handoff,
          headers,
          options: { ...flow, key, context: event.context },
        });
      } catch (error) {
        if (!isUnauthError(error)) throw error;
        return fail(error, headers);
      }
      copySetCookie(headers, event.res);
      return answerUnauthError(() => complete(result), fail);
    }

    const here = new URL(event.req.url);
    const failed = (relocated: RelocatedFailure, headers?: Headers) => {
      if (relocated.returnHost === here.hostname) return fail(relocated.error, headers);
      if (headers) copySetCookie(headers, event.res);
      const { error, returnHost, state } = relocated;
      return handBack(here, {
        returnHost,
        carrier: handoff,
        handed: { failure: handoffFailure(error), state },
      });
    };

    if (!isCallback(provider, event.req)) {
      const relocated = provider.kind === "custom" && carriesIntent(event.req);
      let started: { response: Response } | RelocatedFailure;
      try {
        const intent: FlowIntent<TMemo> = (relocated ? undefined : await onStart?.()) ?? {};
        started = await startFlowWithReturnHost<TMemo>(provider, event.req, {
          ...flow,
          key,
          context: event.context,
          ...definedIntent(intent),
        });
      } catch (error) {
        if (!isUnauthError(error)) throw error;
        return fail(error);
      }
      return "response" in started ? started.response : failed(started);
    }

    const headers = new Headers();
    let completed: CompletedFlow<TProfile, TMemo> | RelocatedFailure;
    try {
      completed = await completeFlowWithReturnHost<TProfile, TMemo>(provider, event.req, {
        ...flow,
        key,
        headers,
        context: event.context,
      });
    } catch (error) {
      if (!isUnauthError(error)) throw error;
      return fail(error, headers);
    }
    if ("error" in completed) return failed(completed, headers);
    copySetCookie(headers, event.res);
    const { result, returnHost, state } = completed;
    if (returnHost !== undefined && state !== undefined && returnHost !== here.hostname) {
      return handBack(here, { returnHost, carrier: handoff, handed: { result, state } });
    }
    return answerUnauthError(() => complete(result), fail);
  };
}

/** `run`'s value, or `fail`'s answer to an `UnauthError` it throws; anything else propagates. */
async function answerUnauthError<T>(
  run: () => Promise<T>,
  fail: (error: UnauthError) => Promise<T>,
): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if (!isUnauthError(error)) throw error;
    return fail(error);
  }
}

/** A plain-text response for an `UnauthError`: its status (500 when it has none) and, below 500, its message; a 5xx carries a generic body. */
function failureResponse(error: UnauthError, headers?: Headers): Response {
  const status = error.status ?? 500;
  const plain = new Headers(headers);
  plain.set("content-type", "text/plain; charset=utf-8");
  plain.set("x-content-type-options", "nosniff");
  return new Response(status >= 500 ? "Sign-in is unavailable." : error.message, {
    status,
    headers: plain,
  });
}

/**
 * Appends `from`'s `Set-Cookie` lines to the event's response headers and, when the framework
 * keeps error responses' headers apart (`errHeaders`), to those too: the expiry of a consumed flow
 * cookie must reach the browser whether the hook answers a success, an error or throws.
 */
function copySetCookie(from: Headers, to: WebRequestEvent["res"]): void {
  for (const line of from.getSetCookie()) {
    to.headers.append("set-cookie", line);
    to.errHeaders?.append("set-cookie", line);
  }
}

/** A `302` to `here` on `returnHost`, carrying `handed` sealed as the handoff token alone. */
async function handBack<TProfile, TMemo>(
  here: URL,
  context: {
    returnHost: string;
    carrier: HandoffCarrier<TProfile, TMemo>;
    handed: Handoff<TProfile, TMemo>;
  },
): Promise<Response> {
  const target = new URL(here);
  target.hostname = context.returnHost;
  const token = await context.carrier.issue(context.handed);
  target.search = `?${HANDOFF_PARAM}=${encodeURIComponent(token)}`;
  return new Response(null, {
    status: 302,
    headers: { "location": target.href, "cache-control": "no-store" },
  });
}
