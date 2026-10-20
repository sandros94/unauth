import type { CacheDriver } from "./_cache.ts";
import { type Fetch, fetchOf } from "./_http.ts";
import { resolveRedirectUri, safeRedirect } from "./_redirect.ts";
import { type FlowCarrierOptions, saveFlow } from "./_transient.ts";
import { buildAuthorizationUrl } from "./authorization-url.ts";
import { resolveProvider } from "./discovery.ts";
import { createNonce, createPkce, createState } from "./random.ts";
import type { FlowRecord, Provider } from "./types.ts";

/** Options of {@link startFlow}. */
export interface StartFlowOptions extends FlowCarrierOptions {
  /** The callback URL registered at the provider. */
  redirectUri?: string;
  /** Origins whose requests may derive `redirectUri` from their own URL, when it is not set. */
  trustedOrigins?: string[];
  /** Where to go after sign-in; kept only when it is a same-origin path. */
  redirect?: string;
  /** Link the provider account to this signed-in user instead of signing in. */
  link?: { userId: string };
  /** Replaces the provider's scopes. */
  scopes?: string[];
  /** Extra authorization parameters (`prompt`, `login_hint`…); never the flow's own. */
  params?: Record<string, string>;
  fetch?: Fetch;
  now?: () => number;
  /** Keep the discovery document here instead of in memory. */
  cache?: CacheDriver;
}

/**
 * Starts a sign-in: a `302` to the provider's authorization endpoint, with a fresh `state`, PKCE
 * and, for OpenID Connect, a `nonce`, remembered in a sealed cookie set on the response (or in
 * `options.store`). A browser holds one flow at a time: a second sign-in started before the first
 * completes replaces it.
 */
export async function startFlow(
  provider: Provider<unknown>,
  request: Request,
  options: StartFlowOptions,
): Promise<Response> {
  const redirectUri = resolveRedirectUri(request, options);
  const resolved = await resolveProvider(provider, {
    fetch: fetchOf(options),
    now: options.now,
    cache: options.cache,
  });
  const pkce = resolved.pkce ? await createPkce() : undefined;
  const redirect = safeRedirect(options.redirect);
  const record: FlowRecord = { provider: provider.id, state: createState(), redirectUri };
  if (pkce) record.verifier = pkce.verifier;
  if (resolved.nonce) record.nonce = createNonce();
  if (redirect !== undefined) record.redirect = redirect;
  if (options.link) record.link = { userId: options.link.userId };
  const url = buildAuthorizationUrl(resolved, {
    redirectUri,
    state: record.state,
    nonce: record.nonce,
    scopes: options.scopes,
    params: options.params,
    pkce:
      pkce &&
      (resolved.pkce === "plain"
        ? { challenge: pkce.verifier, method: "plain" }
        : { challenge: pkce.challenge, method: "S256" }),
  });

  const headers = new Headers({ "location": url.href, "cache-control": "no-store" });
  await saveFlow(record, { request, headers, provider, options });
  return new Response(null, { status: 302, headers });
}
