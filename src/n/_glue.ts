import { type UnauthError, isUnauthError } from "../_internal/error.ts";
import type { AuthorizeOptions } from "./flow/authorize.ts";
import type { CallbackResult } from "./flow/callback.ts";
import type { Provider } from "./flow/types.ts";

/** What a request may add to the authorization leg: where to return, which user links, extra scopes. */
export type AuthorizeIntent = Pick<AuthorizeOptions, "redirect" | "link" | "scopes" | "params">;

/** Options of a framework's `defineOAuthEventHandler`, over its event type. */
export interface OAuthEventHandlerOptions<
  TEvent,
  TProfile = unknown,
  TResult = unknown,
> extends Omit<AuthorizeOptions, keyof AuthorizeIntent> {
  /** Per-request additions to the authorization leg. */
  onAuthorize?: (event: TEvent) => AuthorizeIntent | void | Promise<AuthorizeIntent | void>;
  /** Runs after a completed callback; its return value is the response. */
  onSuccess: (event: TEvent, result: CallbackResult<TProfile>) => TResult | Promise<TResult>;
  /** Answers a failed flow; without it the failure is thrown as the framework's HTTP error. */
  onError?: (event: TEvent, error: UnauthError) => unknown;
}

/** Whether a request to the single OAuth route is the provider's redirect back (the callback leg). */
export function isCallbackLeg(
  provider: Provider<unknown>,
  request: { url: string; method: string },
): boolean {
  const query = new URL(request.url).searchParams;
  if (query.has("code") || query.has("error")) return true;
  return provider.responseMode === "form_post" && request.method === "POST";
}

/** The status and message a framework error carries for an `UnauthError`; 5xx details stay in `cause`. */
export function httpErrorOf(error: UnauthError): { status: number; message: string } {
  const status = error.status ?? 500;
  return { status, message: status >= 500 ? "Sign-in is unavailable." : error.message };
}

/** Runs a flow step, handing an `UnauthError` to `onError` when there is one; anything else propagates. */
export async function runFlow<T>(
  step: () => Promise<T>,
  options: {
    onError?: (error: UnauthError) => unknown;
    toHttpError: (error: UnauthError) => Error;
  },
): Promise<{ ok: true; value: T } | { ok: false; value: unknown }> {
  try {
    return { ok: true, value: await step() };
  } catch (error) {
    if (!isUnauthError(error)) throw error;
    if (options.onError) return { ok: false, value: await options.onError(error) };
    throw options.toHttpError(error);
  }
}
