import type { StartIntent } from "./flow/_internal/carrier/intent.ts";
import type { Provider } from "./flow/types.ts";

/**
 * A web-standard request event: the `Request`, the `Headers` the response is sent with, and
 * optional per-request state. A sign-in handler takes it, and so does an `unjwt/session` definition.
 */
export interface WebRequestEvent {
  readonly req: Request;
  readonly res: {
    readonly headers: Headers;
    /**
     * The headers the framework applies to an error response (a `Response` of status 400 or
     * above, or a thrown error) when it keeps them apart from `headers`, as h3 does: what unauth
     * must set whatever the outcome, the consumed flow cookie's expiry, is written to both.
     */
    readonly errHeaders?: Headers;
  };
  /** Per-request state, handed to the flow session as is; never created. */
  readonly context?: Record<string, unknown>;
}

/** What a request may add to the authorization leg: where to return, a memo, the account, extra scopes. */
export type FlowIntent<TMemo = never> = StartIntent<TMemo>;

/** Whether `request` is the callback leg: a query with `code` or `error`, or a `POST` to a `form_post` provider's route. */
export function isCallback(
  provider: Provider<unknown>,
  request: { url: string; method: string },
): boolean {
  const query = new URL(request.url).searchParams;
  if (query.has("code") || query.has("error")) return true;
  return provider.responseMode === "form_post" && request.method === "POST";
}
