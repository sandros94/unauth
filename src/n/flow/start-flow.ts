import type { CacheDriver } from "./_cache.ts";
import { type Fetch, fetchOf, nowOf } from "./_http.ts";
import { resolveRedirectUri, safeRedirect } from "./_redirect.ts";
import { type FlowCarrierOptions, saveFlow } from "./_transient.ts";
import { buildAuthorizationUrl } from "./authorization-url.ts";
import { resolveProvider } from "./discovery.ts";
import { createNonce, createPkce, createState } from "./random.ts";
import type { CustomProvider, FlowRecord, OAuthProvider, Provider } from "./types.ts";

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
  /**
   * Which account signs in, as the user typed it: the `login_hint` of an OAuth provider, and
   * what a custom provider resolves the account from (an ATProto handle). Some custom providers
   * require it.
   */
  login?: string;
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
 * `options.store`). A custom provider builds the URL itself and seals its own `data` beside the
 * engine's. A browser holds one flow at a time: a second sign-in started before the first
 * completes replaces it.
 */
export async function startFlow(
  provider: Provider<unknown>,
  request: Request,
  options: StartFlowOptions,
): Promise<Response> {
  const redirectUri = resolveRedirectUri(request, {
    redirectUri:
      options.redirectUri ?? (provider.kind === "custom" ? provider.redirectUri : undefined),
    trustedOrigins: options.trustedOrigins,
  });
  const redirect = safeRedirect(options.redirect);
  const record: FlowRecord = { provider: provider.id, state: createState(), redirectUri };
  if (redirect !== undefined) record.redirect = redirect;
  if (options.link) record.link = { userId: options.link.userId };

  const started =
    provider.kind === "custom"
      ? await startCustom(provider, request, { record, redirectUri, options })
      : { url: await startOAuth(provider, { record, redirectUri, options }), relocate: false };

  const headers = new Headers({ "location": started.url.href, "cache-control": "no-store" });
  if (!started.relocate) await saveFlow(record, { request, headers, provider, options });
  return new Response(null, { status: 302, headers });
}

async function startOAuth(
  provider: OAuthProvider<unknown>,
  context: { record: FlowRecord; redirectUri: string; options: StartFlowOptions },
): Promise<URL> {
  const { record, redirectUri, options } = context;
  const resolved = await resolveProvider(provider, {
    fetch: fetchOf(options),
    now: options.now,
    cache: options.cache,
  });
  const pkce = resolved.pkce ? await createPkce() : undefined;
  if (pkce) record.verifier = pkce.verifier;
  if (resolved.nonce) record.nonce = createNonce();
  const params = { ...options.params };
  if (options.login !== undefined && params.login_hint === undefined) {
    params.login_hint = options.login;
  }
  return buildAuthorizationUrl(resolved, {
    redirectUri,
    state: record.state,
    nonce: record.nonce,
    scopes: options.scopes,
    params,
    pkce:
      pkce &&
      (resolved.pkce === "plain"
        ? { challenge: pkce.verifier, method: "plain" }
        : { challenge: pkce.challenge, method: "S256" }),
  });
}

/** The provider's first leg: where to send the user, and whether that is the flow or a fresh start elsewhere. */
async function startCustom(
  provider: CustomProvider<unknown>,
  request: Request,
  context: { record: FlowRecord; redirectUri: string; options: StartFlowOptions },
): Promise<{ url: URL; relocate: boolean }> {
  const { record, redirectUri, options } = context;
  const started = await provider.start({
    request,
    record: { ...record },
    redirectUri,
    login: options.login,
    scopes: options.scopes,
    params: options.params,
    fetch: fetchOf(options),
    now: nowOf(options),
    cache: options.cache,
  });
  if (started.relocate !== undefined) return { url: new URL(started.relocate), relocate: true };
  if (started.data) record.data = started.data;
  if (started.returnHost !== undefined) record.returnHost = started.returnHost;
  return { url: new URL(started.url), relocate: false };
}
