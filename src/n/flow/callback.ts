import { secureCompare } from "unsecure";
import { UnauthError, isUnauthError } from "../../_internal/error.ts";
import { type Fetch, fetchOf, formObject, nowOf, profileError } from "./_http.ts";
import type { CacheDriver } from "./_cache.ts";
import { type FlowCarrierOptions, takeFlow } from "./_transient.ts";
import { resolveProvider } from "./discovery.ts";
import { verifyIdToken } from "./id-token.ts";
import { exchangeCode } from "./token.ts";
import type { IdTokenClaims, OAuthTokens, Provider, ProvenIdentity } from "./types.ts";
import { fetchProfile } from "./userinfo.ts";

/** Options of {@link callback}. */
export interface CallbackOptions extends FlowCarrierOptions {
  /** The response's headers: the consumed flow cookie is expired on them. */
  headers: Headers;
  fetch?: Fetch;
  now?: () => number;
  /** Keep the discovery document and the JWK Set here instead of in memory. */
  cache?: CacheDriver;
}

/** A completed sign-in. What to do with it (sign in, link, redirect) is the caller's call. */
export interface CallbackResult<TProfile = Record<string, unknown>> {
  identity: ProvenIdentity<TProfile>;
  tokens: OAuthTokens;
  /** The user who started the flow to link this account; check it is still the signed-in one. */
  link?: { userId: string };
  /** The same-origin path given to `authorize`. */
  redirect?: string;
}

/**
 * Completes a sign-in from the provider's redirect: consumes the flow (the cookie is expired even
 * when this throws), checks `state` and `iss`, redeems the code, verifies the id_token of an
 * OpenID Connect provider and maps the account through `provider.profile`. Every failure is an
 * `UnauthError` whose message names the stage and whose `cause` holds the detail. A mix-up
 * between providers is caught by the provider `id` bound into the flow record and by the RFC 9207
 * `iss` parameter: with `issuerParameter` on, `iss` must equal `provider.issuer`; otherwise a
 * missing one is accepted but one naming another issuer is not (`ERR_AUTHN_STATE_MISMATCH`, cause
 * `reason: "issuer"`).
 */
export async function callback<TProfile>(
  provider: Provider<TProfile>,
  request: Request,
  options: CallbackOptions,
): Promise<CallbackResult<TProfile>> {
  const record = await takeFlow({ request, headers: options.headers, provider, options });
  const params = await callbackParams(request);

  const error = params.error;
  if (error !== undefined) {
    throw new UnauthError(
      "[unauth/n] The provider did not authorize the sign-in.",
      "ERR_AUTHN_PROVIDER_REFUSED",
      {
        status: 401,
        cause: { error, error_description: params.error_description, error_uri: params.error_uri },
      },
    );
  }
  if (!record) {
    throw new UnauthError(
      "[unauth/n] No sign-in in progress: it expired or was already completed.",
      "ERR_AUTHN_FLOW_EXPIRED",
      {
        status: 401,
      },
    );
  }
  if (record.provider !== provider.id || !secureCompare(record.state, params.state)) {
    throw new UnauthError(
      "[unauth/n] The callback does not belong to this sign-in.",
      "ERR_AUTHN_STATE_MISMATCH",
      {
        status: 401,
        cause: { provider: record.provider },
      },
    );
  }
  if (params.code === undefined) {
    throw new UnauthError(
      "[unauth/n] The provider returned no authorization code.",
      "ERR_AUTHN_PROVIDER_REFUSED",
      {
        status: 401,
        cause: { error: "invalid_request" },
      },
    );
  }

  const fetch = fetchOf(options);
  const { now, cache } = options;
  const resolved = await resolveProvider(provider, { fetch, now, cache });
  if (!issuerMatches(resolved, params.iss)) {
    throw new UnauthError(
      "[unauth/n] The callback does not belong to this sign-in.",
      "ERR_AUTHN_STATE_MISMATCH",
      { status: 401, cause: { provider: provider.id, reason: "issuer" } },
    );
  }
  const tokens = await exchangeCode(resolved, {
    code: params.code,
    codeVerifier: record.verifier,
    redirectUri: record.redirectUri,
    fetch,
    now: options.now,
  });
  const claims =
    resolved.kind === "oidc"
      ? await idTokenClaims(resolved, {
          tokens,
          nonce: record.nonce,
          fetch,
          now: nowOf(options),
          cache,
        })
      : undefined;
  const userinfo = resolved.userinfo ? await fetchProfile(resolved, { tokens, fetch }) : undefined;
  if (claims && userinfo && userinfo.sub !== claims.sub) {
    throw profileError("The userinfo endpoint names another subject than the id_token.");
  }

  const identity = await mapProfile(resolved, { tokens, claims, userinfo, params, fetch });
  const result: CallbackResult<TProfile> = { identity, tokens };
  if (record.link) result.link = record.link;
  if (record.redirect !== undefined) result.redirect = record.redirect;
  return result;
}

async function idTokenClaims(
  provider: Provider<unknown>,
  options: {
    tokens: OAuthTokens;
    nonce?: string;
    fetch: Fetch;
    now: () => number;
    cache?: CacheDriver;
  },
): Promise<IdTokenClaims> {
  const { tokens } = options;
  if (!tokens.id_token || !provider.issuer || !provider.jwks) {
    throw new UnauthError(
      "[unauth/n] The provider returned no id_token.",
      "ERR_AUTHN_ID_TOKEN_INVALID",
      { status: 401 },
    );
  }
  return verifyIdToken(tokens.id_token, {
    issuer: provider.issuer,
    clientId: provider.client.id,
    nonce: options.nonce,
    jwks: provider.jwks,
    accessToken: tokens.access_token,
    fetch: options.fetch,
    now: options.now,
    cache: options.cache,
    insecureHosts: provider.insecureHosts,
  });
}

/**
 * RFC 9207 §2.4: a required `iss` equals the issuer exactly. One sent unasked is compared too
 * when the issuer is known; a provider without one cannot be told apart by it.
 */
function issuerMatches(provider: Provider<unknown>, iss: string | undefined): boolean {
  if (iss === undefined || provider.issuer === undefined) return !provider.issuerParameter;
  return iss === provider.issuer;
}

async function mapProfile<TProfile>(
  provider: Provider<TProfile>,
  context: Parameters<Provider<TProfile>["profile"]>[0],
): Promise<ProvenIdentity<TProfile>> {
  let profile: Awaited<ReturnType<Provider<TProfile>["profile"]>>;
  try {
    profile = await provider.profile(context);
  } catch (error) {
    if (isUnauthError(error)) throw error;
    throw profileError("The provider's account data could not be read.", error);
  }
  if (typeof profile?.subject !== "string" || profile.subject === "") {
    throw profileError("The provider's account data names no subject.");
  }
  return { ...profile, provider: provider.id, tokens: context.tokens };
}

/** The redirect's parameters: the query, or a `form_post` body (OAuth 2.0 Form Post Response Mode). */
async function callbackParams(request: Request): Promise<Record<string, string>> {
  const type = request.headers.get("content-type") ?? "";
  if (request.method === "POST" && type.includes("application/x-www-form-urlencoded")) {
    return formObject(new URLSearchParams(await request.text()));
  }
  return formObject(new URL(request.url).searchParams);
}
