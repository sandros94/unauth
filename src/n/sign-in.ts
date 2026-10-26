import type { UnauthError } from "../error.ts";
import { type SignInKey, flowKeyResolver } from "./_internal/flow-key.ts";
import { configError } from "./flow/_internal/http/shared.ts";
import { safeRedirect } from "./flow/_internal/redirect.ts";
import type { FlowResult } from "./flow/types.ts";
import type { StartFlowOptions } from "./flow/start-flow.ts";
import type { Provider } from "./flow/types.ts";
import { signInRoute } from "./_internal/sign-in-route.ts";
import type { FlowIntent, WebRequestEvent } from "./request-event.ts";

/**
 * Options of {@link defineSignInHandler}: the flow, its key, and the application's hooks. Each hook
 * takes the request's event first, then its own argument.
 */
export interface SignInHandlerOptions<
  TProfile = unknown,
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
>
  extends Omit<StartFlowOptions, keyof FlowIntent | "key" | "context">, SignInKey {
  /**
   * An origin whose requests derive `redirectUri` from their own URL, and whose forms may start a
   * sign-in that links an account or names it: added to `trustedOrigins`.
   */
  origin?: string;
  /**
   * Where the browser lands when `onSuccess` answers nothing; a same-origin `redirect` the flow
   * carries wins over it.
   *
   * @default "/"
   */
  redirect?: string;
  /**
   * Per-request additions to the authorization leg. A `memo` carries what the application needs
   * back at the callback, such as the signed-in user asking to link this account; sealed in the
   * flow, it comes back as `result.memo`. A start returning `memo`, or `loginHint` for a custom
   * provider, is accepted only as a `POST` from the application's own origin
   * (`ERR_AUTHN_CROSS_SITE_START` otherwise): start those sign-ins from a form. An `UnauthError`
   * it throws is answered as a failed flow; anything else propagates as it is.
   */
  onStart?: (event: TEvent) => FlowIntent<TMemo> | void | Promise<FlowIntent<TMemo> | void>;
  /**
   * Runs after a completed callback: the application writes its session, or acts on `result.memo`.
   * Its return value is the response; `undefined` answers a `302` to the flow's `redirect`, else
   * to `redirect`. What it throws propagates as it is.
   */
  onSuccess: (
    event: TEvent,
    result: FlowResult<TProfile, NoInfer<TMemo>>,
  ) => TResult | Promise<TResult>;
  /**
   * Answers a failed flow, always an `UnauthError`; its return value is the response. Without it
   * the failure is answered with a plain `Response` carrying the error's status (500 when it has
   * none): its message below 500, a generic body otherwise. What `onSuccess` throws, and anything
   * but an `UnauthError` from `onStart`, is not a failed flow and propagates as it is.
   */
  onError?: (
    event: TEvent,
    error: UnauthError,
  ) => SignInAnswer<TResult> | Response | Promise<SignInAnswer<TResult> | Response>;
}

/** What a sign-in answers besides a `Response`: `onSuccess`'s return type without `void`. */
export type SignInAnswer<TResult> = Exclude<TResult, void>;

/**
 * One route for both legs of a sign-in: a handler taking a web-standard request event, mounted
 * without a method filter (it answers `GET` and `POST`, `405` otherwise). A request without
 * `code` or `error` (or a `form_post` body) starts the flow with `onStart`'s intent and answers
 * the redirect to the provider; the callback completes it and calls `onSuccess`, which writes the
 * application's session. The handler returns `onSuccess`'s value, or a `302` to the landing path
 * when that is `undefined`. A failed flow is an `UnauthError`, answered by `onError` or by a plain
 * `Response` with its status.
 *
 * Every hook takes the event first. The annotation on the first hook's `event` types every hook
 * and the handler: put the framework's event type on the first hook written; `result` and `memo`
 * stay inferred.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` without `onSuccess`, for a `redirect` that is not a
 * same-origin path, an `origin` that is not an absolute URL, or a `key` that is missing, a string
 * or not symmetric.
 *
 * @example
 * import type { H3Event } from "h3";
 *
 * // Mounted without a method filter: a sign-in starts from a link or a form, a memo from a form only.
 * const handler = defineSignInHandler(github, {
 *   key,
 *   origin: "https://app.example",
 *   onStart: async (event: H3Event) => {
 *     const session = await useAuthSession(event);
 *     return session.id ? { memo: { userId: session.data.userId } } : undefined;
 *   },
 *   onSuccess: async (event, { identity, memo }) => {
 *     // `event` is an `H3Event`; `memo` has the type `onStart` returned.
 *   },
 * });
 */
export function defineSignInHandler<
  TProfile,
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
>(
  provider: Provider<TProfile>,
  options: SignInHandlerOptions<TProfile, TResult, TEvent, TMemo>,
): (event: TEvent) => Promise<Response | SignInAnswer<TResult>> {
  const { key, origin, redirect, onStart, onSuccess, onError, ...flow } = options;
  if (typeof onSuccess !== "function") {
    throw configError(
      "The sign-in needs an `onSuccess`: what a completed sign-in writes is the application's call.",
    );
  }
  if (redirect !== undefined && safeRedirect(redirect) === undefined) {
    throw configError(
      `The sign-in \`redirect\` must be a same-origin path such as "/account", got ${JSON.stringify(redirect)}.`,
    );
  }
  const trustedOrigins =
    origin === undefined ? flow.trustedOrigins : [...(flow.trustedOrigins ?? []), originOf(origin)];
  return signInRoute<TProfile, SignInAnswer<TResult>, TEvent, TMemo>(provider, {
    flow: { ...flow, trustedOrigins },
    key: flowKeyResolver(key),
    steps: (event) => ({
      onStart: onStart && (() => onStart(event)),
      onError: onError && ((error) => onError(event, error)),
      complete: async (result) => {
        const answer = await onSuccess(event, result);
        if (isAnswer(answer)) return answer;
        return new Response(null, {
          status: 302,
          headers: {
            "location": result.redirect ?? redirect ?? "/",
            "cache-control": "no-store",
          },
        });
      },
    }),
  });
}

/** `value` as an origin; `ERR_UNAUTH_CONFIG_INVALID` when it is not an absolute URL. */
function originOf(value: string): string {
  try {
    return new URL(value).origin;
  } catch (error) {
    throw configError(
      `The sign-in \`origin\` must be an absolute URL such as "https://app.example", got ${JSON.stringify(value)}.`,
      error,
    );
  }
}

function isAnswer<TResult>(value: TResult): value is SignInAnswer<TResult> & TResult {
  return value !== undefined;
}
