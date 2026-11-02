import { isUnauthError } from "../../../error.ts";
import { fetchOf } from "./http/shared.ts";
import { nowOf } from "../../../_internal/shared.ts";
import { resolveRedirectUri, safeRedirect } from "./redirect.ts";
import { assertFormStart } from "./form-start.ts";
import { type ResumedIntent, resumeIntent, withSealedIntent } from "./carrier/intent.ts";
import type { RelocatedFailure } from "./carrier/handoff.ts";
import { saveFlow } from "./carrier/transient.ts";
import { buildAuthorizationUrl } from "../authorization-url.ts";
import { resolveProvider } from "../discovery.ts";
import { createNonce, createPkce, createState } from "../random.ts";
import type { StartFlowOptions } from "../start-flow.ts";
import type { CustomProvider, FlowRecord, OAuthProvider, Provider } from "../types.ts";

/**
 * `startFlow`, reporting instead of throwing an `UnauthError` raised once a relocated start knows
 * the host it began on: the sign-in route hands that failure back there, beside the flow's
 * `state`. Before then, or on a start that was not relocated, it throws as `startFlow` does.
 */
export async function startFlowWithReturnHost<TMemo = never>(
  provider: Provider<unknown>,
  request: Request,
  options: StartFlowOptions<TMemo>,
): Promise<{ response: Response } | RelocatedFailure> {
  const resumed: ResumedIntent<TMemo> =
    provider.kind === "custom"
      ? await resumeIntent(request, { provider: provider.id, options })
      : { options };
  const returned =
    resumed.returnHost !== undefined && resumed.returnHost !== new URL(request.url).hostname
      ? { returnHost: resumed.returnHost, state: resumed.state }
      : undefined;
  try {
    return { response: await startResumed(provider, request, { resumed, returned }) };
  } catch (error) {
    if (returned === undefined || !isUnauthError(error)) throw error;
    return { error, ...returned };
  }
}

/** The start once its intent is resumed; `returned`, the other host a relocated start began on. */
async function startResumed<TMemo>(
  provider: Provider<unknown>,
  request: Request,
  context: { resumed: ResumedIntent<TMemo>; returned?: { returnHost: string } },
): Promise<Response> {
  const { resumed, returned } = context;
  let { options } = resumed;
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
  const registered = provider.kind === "custom" ? provider.redirectUri : undefined;
  const redirectUri = resolveRedirectUri(request, {
    redirectUri: options.redirectUri ?? registered,
    trustedOrigins: options.trustedOrigins,
    registered,
  });
  const redirect = safeRedirect(options.redirect);
  const record: FlowRecord<TMemo> = {
    provider: provider.id,
    state: resumed.state ?? createState(),
    redirectUri,
  };
  if (redirect !== undefined) record.redirect = redirect;
  if (options.memo !== undefined) record.memo = options.memo;
  if (returned !== undefined) record.returnHost = returned.returnHost;

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
