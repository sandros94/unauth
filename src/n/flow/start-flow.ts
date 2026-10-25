import type { CacheDriver } from "./_internal/cache/load.ts";
import { type Fetch, fetchOf, nowOf } from "./_internal/http/shared.ts";
import { resolveRedirectUri, safeRedirect } from "./_internal/redirect.ts";
import { assertFormStart } from "./_internal/form-start.ts";
import { type ResumedIntent, resumeIntent, withSealedIntent } from "./_internal/carrier/intent.ts";
import { type FlowCarrierOptions, saveFlow } from "./_internal/carrier/transient.ts";
import { buildAuthorizationUrl } from "./authorization-url.ts";
import { resolveProvider } from "./discovery.ts";
import { createNonce, createPkce, createState } from "./random.ts";
import type { CustomProvider, FlowRecord, OAuthProvider, Provider } from "./types.ts";

/** Options of {@link startFlow}. */
export interface StartFlowOptions<TMemo = never> extends FlowCarrierOptions {
  /** The callback URL registered at the provider. */
  redirectUri?: string;
  /**
   * Origins whose requests may derive `redirectUri` from their own URL, when it is not set,
   * whose forms may start a sign-in that carries a `memo` or names the account (`loginHint`),
   * and whose starts a custom provider may relocate. A custom provider's own `trustedOrigins`
   * are added.
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
   * (discovery, keys, handles, servers): the place to refuse private network ranges when the
   * server can reach some.
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
 * relocated, since the completed sign-in is returned to that origin: `ERR_UNAUTH_CONFIG_INVALID`
 * for any other.
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
  const resumed: ResumedIntent<TMemo> =
    provider.kind === "custom"
      ? await resumeIntent(request, { provider: provider.id, options })
      : { options };
  options = resumed.options;
  if (provider.kind === "custom" && provider.trustedOrigins?.length) {
    options = {
      ...options,
      trustedOrigins: [...(options.trustedOrigins ?? []), ...provider.trustedOrigins],
    };
  }
  const steerable =
    options.memo !== undefined || (provider.kind === "custom" && options.loginHint !== undefined);
  if (steerable && resumed.returnHost === undefined) {
    assertFormStart(request, options.trustedOrigins);
  }
  const redirectUri = resolveRedirectUri(request, {
    redirectUri:
      options.redirectUri ?? (provider.kind === "custom" ? provider.redirectUri : undefined),
    trustedOrigins: options.trustedOrigins,
  });
  const redirect = safeRedirect(options.redirect);
  const record: FlowRecord<TMemo> = {
    provider: provider.id,
    state: resumed.state ?? createState(),
    redirectUri,
  };
  if (redirect !== undefined) record.redirect = redirect;
  if (options.memo !== undefined) record.memo = options.memo;
  if (resumed.returnHost !== undefined && resumed.returnHost !== new URL(request.url).hostname) {
    record.returnHost = resumed.returnHost;
  }

  const started =
    provider.kind === "custom"
      ? await startCustom(provider, request, { record, redirectUri, options })
      : { url: await startOAuth(provider, { record, redirectUri, options }), relocate: false };

  const location = started.relocate
    ? await withSealedIntent(started.url, { request, options, record })
    : started.url;
  const headers = new Headers({ "location": location.href, "cache-control": "no-store" });
  await saveFlow(record, { request, headers, provider, options });
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
  if (options.loginHint !== undefined && params.login_hint === undefined) {
    params.login_hint = options.loginHint;
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
    record: { provider: record.provider, state: record.state, redirectUri: record.redirectUri },
    redirectUri,
    loginHint: options.loginHint,
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
