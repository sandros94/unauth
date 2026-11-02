import type { CacheDriver } from "../../_internal/cache-driver.ts";
import type { Fetch } from "./_internal/http/shared.ts";
import { startFlowWithReturnHost } from "./_internal/start.ts";
import type { FlowCarrierOptions } from "./_internal/carrier/transient.ts";
import type { Provider } from "./types.ts";

/** Options of {@link startFlow}. */
export interface StartFlowOptions<TMemo = never> extends FlowCarrierOptions {
  /** The callback URL registered at the provider. */
  redirectUri?: string;
  /**
   * Origins whose requests may derive `redirectUri` from their own URL, when it is not set,
   * whose forms may start a sign-in that carries a `memo` or names the account (`loginHint`),
   * and whose starts a custom provider may relocate. A custom provider's own `trustedOrigins`
   * are added. Once listed, a start is accepted on these origins and the callback's only,
   * `ERR_AUTHN_ORIGIN_UNTRUSTED` (421) otherwise, `redirectUri` set or not. List every origin the
   * sign-in runs on, the development ones included (`http://localhost:3000`,
   * `http://127.0.0.1:3000`); origins are matched exactly, as the redirect URIs registered at the
   * provider are.
   */
  trustedOrigins?: string[];
  /** Where to go after sign-in; kept only when it is a same-origin path. */
  redirect?: string;
  /**
   * A memo: whatever the application needs back at the callback, such as the signed-in user who
   * asked to link this provider account. It is sealed in the flow record, out of the browser's
   * reach, and handed back untouched as `FlowResult.memo`; it must survive a JSON round trip.
   */
  memo?: TMemo;
  /**
   * Which account signs in, as the user typed it: the `login_hint` of an OAuth provider, and
   * what a custom provider resolves the account from (an ATProto handle). Some custom providers
   * require it.
   */
  loginHint?: string;
  /** Replaces the provider's scopes. */
  scopes?: string[];
  /** Extra authorization parameters (`prompt`, `login_hint`…); never the flow's own. */
  params?: Record<string, string>;
  /**
   * Replaces the global `fetch` for every request to a provider or to what a sign-in resolves
   * (discovery, keys, handles, servers): the place to refuse private addresses a public name
   * resolves to, when the server can reach some.
   * - Node: an undici `Agent` refusing non-unicast addresses at connect time (`playgrounds/nitro/server/utils/public-fetch.ts`).
   * - Cloudflare Workers: the platform refuses private ranges; nothing to inject.
   * - Deno and Bun: no connect hook; restrict with `--allow-net` or egress rules.
   */
  fetch?: Fetch;
  now?: () => number;
  /** Keep the discovery document here instead of in memory. */
  cache?: CacheDriver;
}

/**
 * Starts a sign-in: a `302` to the provider's authorization endpoint, with a fresh `state`, PKCE
 * and, for OpenID Connect, a `nonce`, remembered in a sealed cookie set on the response (or in
 * `options.store`). A custom provider builds the URL itself and seals its own `data` beside the
 * engine's. A browser holds one flow at a time: a second sign-in started before the first
 * completes replaces it.
 *
 * A custom provider's relocation records the flow on the host it leaves, as any start does, and
 * seals the request's intent (`redirect`, `memo`, `loginHint`, `scopes`, `params`), its host and
 * the flow's provider and `state` into the relocation URL as `unauth_intent`. The relocated start
 * reads them back: the intent's members win over the options it was given, the host, when it is
 * another, is recorded as `returnHost`, and the flow continues under the same `state`, which the
 * completed sign-in handed back to that host is checked against. The token opens once, within a
 * minute, for the same provider; one that does not is `ERR_AUTHN_FLOW_EXPIRED`, one sealed for
 * another provider `ERR_AUTHN_STATE_MISMATCH`. Only a start from one of `trustedOrigins` is
 * relocated, since the completed sign-in is returned to that origin: `ERR_AUTHN_ORIGIN_UNTRUSTED`
 * (421) for any other.
 *
 * A start that carries a `memo`, or names the account of a custom provider (`loginHint`), is
 * taken only from a form submitted on the application's own pages: a `POST` whose `Origin` is the
 * request's or one of `trustedOrigins`. Anything else is `ERR_AUTHN_CROSS_SITE_START` (403): a
 * cross-site navigation must not seal the signed-in user's memo, or hand the flow's `state` to a
 * server the request picked, into a flow the user never asked for. A relocated start opened from
 * a sealed intent was checked where it began.
 */
export async function startFlow<TMemo = never>(
  provider: Provider<unknown>,
  request: Request,
  options: StartFlowOptions<TMemo>,
): Promise<Response> {
  const started = await startFlowWithReturnHost(provider, request, options);
  if ("error" in started) throw started.error;
  return started.response;
}
