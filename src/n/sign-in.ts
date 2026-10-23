import type { UnauthError } from "../_internal/error.ts";
import { type SignInKey, flowKeyResolver } from "./_flow-key.ts";
import { type AuthSessionData, toSessionData } from "./_session-data.ts";
import { configError, nowOf } from "./flow/_http.ts";
import { safeRedirect } from "./flow/_redirect.ts";
import type { FlowResult } from "./flow/complete-flow.ts";
import type { StartFlowOptions } from "./flow/start-flow.ts";
import type { Provider, ProvenIdentity } from "./flow/types.ts";
import { signInRoute } from "./_sign-in-route.ts";
import type { FlowIntent, HandlerEvent } from "./handler.ts";

/**
 * The part of a session manager a sign-in writes through: a sign-in `clear`s the session, then
 * `update`s it with its data, so nothing of whoever was signed in before carries over and the
 * session id is a new one. An `unjwt/session` manager for `TSession` is one.
 */
export interface SessionWriter<TSession> {
  update(data: TSession): Promise<unknown>;
  clear(): Promise<unknown>;
}

/** The application's session for a request, as its `useAuthSession(event)` util returns it. */
export type SessionAccess<TSession extends object, TEvent extends HandlerEvent = HandlerEvent> = (
  event: TEvent,
) => Promise<SessionWriter<TSession>>;

/** Maps a proven identity to the session data a sign-in writes. */
export type ToSession<
  TSession,
  TEvent extends HandlerEvent = HandlerEvent,
  TProfile = Record<string, unknown>,
> = (
  identity: ProvenIdentity<TProfile>,
  context: { event: TEvent; now: number },
) => TSession | Promise<TSession>;

/** Options of {@link defineSignInHandler}: the flow, its key, and how a completed sign-in ends. */
export type SignInHandlerOptions<
  TProfile = unknown,
  TSession extends object = AuthSessionData,
  TResult = unknown,
  TEvent extends HandlerEvent = HandlerEvent,
> = SignInFlowOptions<TResult, TEvent> &
  SignInKey &
  (SessionEnding<TProfile, TSession, TResult, TEvent> | ResponseEnding<TProfile, TResult, TEvent>);

/**
 * One route for both legs of a sign-in, the handler h3 v2, Nitro 3 and `nuxt/server` take as it
 * is. With `session`, a completed callback writes `toSession`'s data through it, then answers
 * with `onSuccess`'s value or a `302` to the landing path. Without it, `onSuccess` answers alone.
 * Failures are `UnauthError`s, answered by `onError` or by a plain response with their status.
 * Narrow `TEvent` by annotating the event of `session`, `onSuccess` or another hook.
 */
export function defineSignInHandler<
  TProfile,
  TResult = never,
  TEvent extends HandlerEvent = HandlerEvent,
>(
  provider: Provider<TProfile>,
  options: SignInFlowOptions<TResult, TEvent> &
    SignInKey &
    SessionEnding<TProfile, AuthSessionData, TResult, TEvent> & { toSession?: never },
): (event: TEvent) => Promise<Response | TResult>;
export function defineSignInHandler<
  TProfile,
  TSession extends object,
  TResult = never,
  TEvent extends HandlerEvent = HandlerEvent,
>(
  provider: Provider<TProfile>,
  options: SignInFlowOptions<TResult, TEvent> &
    SignInKey &
    SessionEnding<TProfile, TSession, TResult, TEvent> & {
      toSession: ToSession<TSession, TEvent, TProfile>;
    },
): (event: TEvent) => Promise<Response | TResult>;
export function defineSignInHandler<TProfile, TResult, TEvent extends HandlerEvent = HandlerEvent>(
  provider: Provider<TProfile>,
  options: SignInFlowOptions<TResult, TEvent> &
    SignInKey &
    ResponseEnding<TProfile, TResult, TEvent>,
): (event: TEvent) => Promise<Response | TResult>;
export function defineSignInHandler<TProfile, TResult, TEvent extends HandlerEvent>(
  provider: Provider<TProfile>,
  options: SignInHandlerOptions<TProfile, object, TResult, TEvent>,
): (event: TEvent) => Promise<Response | TResult> {
  const { key, origin, onStart, onError, session, toSession, redirect, onSuccess, ...flow } =
    options;
  if (session === undefined && onSuccess === undefined) {
    throw configError("Give the sign-in a `session` to write, or an `onSuccess` to answer it.");
  }
  if (redirect !== undefined && safeRedirect(redirect) === undefined) {
    throw configError(
      `The sign-in \`redirect\` must be a same-origin path such as "/account", got ${JSON.stringify(redirect)}.`,
    );
  }
  const trustedOrigins =
    origin === undefined ? flow.trustedOrigins : [...(flow.trustedOrigins ?? []), originOf(origin)];
  const now = nowOf(flow);
  return signInRoute<TProfile, TResult, TEvent>(provider, {
    flow: { ...flow, trustedOrigins },
    key: flowKeyResolver(key),
    onStart: async (event) => {
      const intent = (await onStart?.(event)) ?? {};
      if (intent.link !== undefined && onSuccess === undefined) throw linkNeedsOnSuccess();
      return intent;
    },
    onError,
    complete: async (event, result, fail) => {
      if (result.link !== undefined && onSuccess === undefined) return fail(linkNeedsOnSuccess());
      if (session !== undefined && result.link === undefined) {
        const context = { event, now: now() };
        const data = toSession
          ? await toSession(result.identity, context)
          : toSessionData(result.identity, context);
        const writer = await session(event);
        await writer.clear();
        await writer.update(data);
      }
      if (onSuccess) return onSuccess(event, result);
      return new Response(null, {
        status: 302,
        headers: { "location": result.redirect ?? redirect ?? "/", "cache-control": "no-store" },
      });
    },
  });
}

/** The options of both legs, but the flow key and the request's intent. */
export interface SignInFlowOptions<TResult, TEvent extends HandlerEvent> extends Omit<
  StartFlowOptions,
  keyof FlowIntent | "key"
> {
  /** An origin whose requests derive `redirectUri` from their own URL: added to `trustedOrigins`. */
  origin?: string;
  /**
   * Per-request additions to the authorization leg. A `link` intent without `onSuccess` is
   * refused here, before the user leaves for the provider. What it throws propagates as it is.
   */
  onStart?: (event: TEvent) => FlowIntent | void | Promise<FlowIntent | void>;
  /**
   * Answers a failed flow, which is always an `UnauthError`; its return value is the response.
   * Without it the failure is answered with a plain `Response` carrying the error's status: its
   * message for a 4xx, nothing for a 5xx. What the application's own hooks (`onStart`, `toSession`,
   * `onSuccess`) throw is not a failed flow: it propagates as it is, for the framework to answer.
   */
  onError?: (event: TEvent, error: UnauthError) => TResult | Response | Promise<TResult | Response>;
}

/** A sign-in that writes the application's session. */
export interface SessionEnding<
  TProfile,
  TSession extends object,
  TResult,
  TEvent extends HandlerEvent,
> {
  /**
   * The application's session util; a completed sign-in clears the session it returns, then
   * writes `toSession`'s data through it.
   */
  session: SessionAccess<NoInfer<TSession>, TEvent>;
  /** The session data of a sign-in; {@link toSessionData} when absent. What it throws propagates as it is. */
  toSession?: ToSession<TSession, TEvent, TProfile>;
  /**
   * Where the browser lands when `onSuccess` does not answer; a same-origin `redirect` the flow
   * carries wins over it.
   *
   * @default "/"
   */
  redirect?: string;
  /**
   * Runs after the session is written; its return value is the response. A `link` intent
   * (`result.link`) is the application's to handle: the session is not written, and a sign-in
   * without `onSuccess` refuses it with `ERR_UNAUTH_CONFIG_INVALID`.
   */
  onSuccess?: (event: TEvent, result: FlowResult<TProfile>) => TResult | Promise<TResult>;
}

/** A sign-in whose `onSuccess` does everything after the callback. */
export interface ResponseEnding<TProfile, TResult, TEvent extends HandlerEvent> {
  session?: never;
  toSession?: never;
  redirect?: never;
  /** Runs after a completed callback; its return value is the response. */
  onSuccess: (event: TEvent, result: FlowResult<TProfile>) => TResult | Promise<TResult>;
}

/** `ERR_UNAUTH_CONFIG_INVALID`: a `link` intent was asked for with nothing to handle it. */
function linkNeedsOnSuccess(): UnauthError<"ERR_UNAUTH_CONFIG_INVALID"> {
  return configError(
    "A `link` intent needs `onSuccess`: linking an account to the signed-in user is the application's call.",
  );
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
