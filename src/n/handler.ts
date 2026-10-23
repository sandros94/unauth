import type { StartFlowOptions } from "./flow/start-flow.ts";
import type { Provider } from "./flow/types.ts";

/**
 * A request event a handler answers: the web-standard `{ req, res, context }` that h3 v2, Nitro 3
 * and a `nuxt/server` handler receive, with the `res` the response is sent with. It is one of the
 * events an `unjwt/session` definition takes.
 */
export interface HandlerEvent {
  readonly req: Request;
  readonly res: { readonly headers: Headers };
  /** Per-request state shared with the framework. */
  readonly context?: Record<string, unknown>;
}

/** What a request may add to the authorization leg: where to return, which user links, extra scopes. */
export type FlowIntent = Pick<
  StartFlowOptions,
  "redirect" | "link" | "login" | "scopes" | "params"
>;

/** Whether a request to the single OAuth route is the provider's redirect back (the callback leg). */
export function isCallback(
  provider: Provider<unknown>,
  request: { url: string; method: string },
): boolean {
  const query = new URL(request.url).searchParams;
  if (query.has("code") || query.has("error")) return true;
  return provider.responseMode === "form_post" && request.method === "POST";
}
