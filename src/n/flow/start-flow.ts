import type { CacheDriver } from "./_internal/cache/load.ts";
import { type Fetch, fetchOf, nowOf } from "./_internal/http/shared.ts";
import { resolveRedirectUri, safeRedirect } from "./_internal/redirect.ts";
import { resumeIntent, withSealedIntent } from "./_internal/carrier/intent.ts";
import { type FlowCarrierOptions, saveFlow } from "./_internal/carrier/transient.ts";
import { buildAuthorizationUrl } from "./authorization-url.ts";
import { resolveProvider } from "./discovery.ts";
import { createNonce, createPkce, createState } from "./random.ts";
import type { CustomProvider, FlowRecord, OAuthProvider, Provider } from "./types.ts";

/** Options of {@link startFlow}. */
export interface StartFlowOptions<TLink = never> extends FlowCarrierOptions {
  /** The callback URL registered at the provider. */
  redirectUri?: string;
  /** Origins whose requests may derive `redirectUri` from their own URL, when it is not set. */
  trustedOrigins?: string[];
  /** Where to go after sign-in; kept only when it is a same-origin path. */
  redirect?: string;
  /**
   * A link intent: whatever the application needs to recognise, at the callback, the signed-in
   * user who asked to link this provider account. It is sealed in the flow record, out of the
   * browser's reach, and handed back untouched as `FlowResult.link`; it must survive a JSON round
   * trip.
   */
  link?: TLink;
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
 *
 * A custom provider's relocation records nothing: the request's intent (`redirect`, `link`,
 * `login`, `scopes`, `params`) and its host are sealed into the relocation URL as `unauth_intent`,
 * and the relocated start reads them back, the intent's members winning over the options it was
 * given and the host, when it is another, recorded as `returnHost`. That token opens once, within
 * a minute; one that does not is `ERR_AUTHN_FLOW_EXPIRED`.
 */
export async function startFlow<TLink = never>(
  provider: Provider<unknown>,
  request: Request,
  options: StartFlowOptions<TLink>,
): Promise<Response> {
  const resumed = provider.kind === "custom" ? await resumeIntent(request, options) : { options };
  options = resumed.options;
  const redirectUri = resolveRedirectUri(request, {
    redirectUri:
      options.redirectUri ?? (provider.kind === "custom" ? provider.redirectUri : undefined),
    trustedOrigins: options.trustedOrigins,
  });
  const redirect = safeRedirect(options.redirect);
  const record: FlowRecord<TLink> = { provider: provider.id, state: createState(), redirectUri };
  if (redirect !== undefined) record.redirect = redirect;
  if (options.link !== undefined) record.link = options.link;
  if (resumed.returnHost !== undefined && resumed.returnHost !== new URL(request.url).hostname) {
    record.returnHost = resumed.returnHost;
  }

  const started =
    provider.kind === "custom"
      ? await startCustom(provider, request, { record, redirectUri, options })
      : { url: await startOAuth(provider, { record, redirectUri, options }), relocate: false };

  const location = started.relocate
    ? await withSealedIntent(started.url, { request, options })
    : started.url;
  const headers = new Headers({ "location": location.href, "cache-control": "no-store" });
  if (!started.relocate) await saveFlow(record, { request, headers, provider, options });
  return new Response(null, { status: 302, headers });
}

async function startOAuth(
  provider: OAuthProvider<unknown>,
  context: { record: FlowRecord; redirectUri: string; options: StartFlowOptions<unknown> },
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
  context: { record: FlowRecord; redirectUri: string; options: StartFlowOptions<unknown> },
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
  return { url: new URL(started.url), relocate: false };
}
