import { type Fetch, configError, fetchOf, nowOf } from "./_internal/http/shared.ts";
import { postForm } from "./_internal/http/form.ts";
import { authenticateClient } from "./_internal/client-auth.ts";
import { parseTokenResponse } from "./_internal/token-response.ts";
import type { CacheDriver } from "./_internal/cache/load.ts";
import { verifyProviderIdToken } from "./_internal/provider-id-token.ts";
import { resolveProvider } from "./discovery.ts";
import type { IdTokenClaims, OAuthTokens, OAuthProvider } from "./types.ts";

/** Options of {@link exchangeCode}. */
export interface ExchangeCodeOptions {
  code: string;
  /** The PKCE verifier of the authorization request. */
  codeVerifier?: string;
  /** Exactly the `redirect_uri` of the authorization request. */
  redirectUri: string;
  fetch?: Fetch;
  /** Clock in ms, for client assertions. */
  now?: () => number;
}

/**
 * Redeems an authorization code (RFC 6749 §4.1.3). A refusal, whether sent as 400, 401 or a 200
 * carrying `error`, and an unusable body throw `ERR_AUTHN_TOKEN_EXCHANGE` (401) with the provider's
 * error in `cause`; an endpoint that gives no answer at all (unreachable, past the deadline, over
 * the body cap) throws `ERR_AUTHN_PROVIDER_ERROR` (502) like every provider endpoint.
 */
export function exchangeCode(
  provider: OAuthProvider<unknown>,
  options: ExchangeCodeOptions,
): Promise<OAuthTokens> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: options.code,
    redirect_uri: options.redirectUri,
  });
  if (options.codeVerifier !== undefined) body.set("code_verifier", options.codeVerifier);
  return tokenRequest(provider, body, options);
}

/** Options of {@link refreshTokens}. */
export interface RefreshTokensOptions {
  refreshToken: string;
  /** Narrower scopes for the new access token. */
  scopes?: string[];
  /**
   * The `sub` of the account whose tokens these are, from its sign-in: a refreshed id_token must
   * name it.
   */
  subject?: string;
  fetch?: Fetch;
  now?: () => number;
  /** Keep the discovery document and the JWK Set here instead of in memory. */
  cache?: CacheDriver;
}

/** What {@link refreshTokens} returns: the new tokens, with the refreshed id_token's verified claims. */
export interface RefreshedTokens extends OAuthTokens {
  /** Present when an OpenID Connect provider returned an id_token. */
  claims?: IdTokenClaims;
}

/**
 * Trades a refresh token for new tokens (RFC 6749 §6); the old refresh token is kept when the
 * provider does not rotate it. A `discovery` provider is resolved first (see `resolveProvider`).
 * An id_token from an OpenID Connect provider is verified as at sign-in (OIDC Core §12.2): its
 * signature, issuer, audience, `exp`, `iat`, `at_hash` and, with `subject`, that `sub` names that
 * account; a `nonce` is not required. Its claims are returned in `claims`.
 *
 * A refusal or an unusable body throws `ERR_AUTHN_TOKEN_EXCHANGE` (401); an id_token failing
 * verification throws `ERR_AUTHN_ID_TOKEN_INVALID` (401), `cause.reason` `"subject"` when it names
 * another account; an endpoint that gives no answer throws `ERR_AUTHN_PROVIDER_ERROR` (502).
 */
export async function refreshTokens(
  provider: OAuthProvider<unknown>,
  options: RefreshTokensOptions,
): Promise<RefreshedTokens> {
  const fetch = fetchOf(options);
  const now = nowOf(options);
  const resolved = await resolveProvider(provider, { fetch, now, cache: options.cache });
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: options.refreshToken,
  });
  if (options.scopes) body.set("scope", options.scopes.join(resolved.scopeSeparator));
  const tokens = await tokenRequest(resolved, body, { fetch, now });
  const refreshed: RefreshedTokens = {
    ...tokens,
    refresh_token: tokens.refresh_token ?? options.refreshToken,
  };
  if (resolved.kind === "oidc" && tokens.id_token !== undefined) {
    refreshed.claims = await verifyProviderIdToken(resolved, {
      idToken: tokens.id_token,
      accessToken: tokens.access_token,
      subject: options.subject,
      fetch,
      now,
      cache: options.cache,
    });
  }
  return refreshed;
}

async function tokenRequest(
  provider: OAuthProvider<unknown>,
  body: URLSearchParams,
  options: { fetch?: Fetch; now?: () => number },
): Promise<OAuthTokens> {
  const endpoint = provider.token;
  if (!endpoint) {
    throw configError(
      `OAuthProvider ${JSON.stringify(provider.id)} has no "token" endpoint yet; pass it through resolveProvider() first.`,
    );
  }
  for (const [name, value] of Object.entries(provider.tokenParams)) {
    if (!body.has(name)) body.set(name, value);
  }
  const headers = new Headers();
  await authenticateClient(provider, { body, headers, endpoint, now: nowOf(options) });
  const answer = await postForm(endpoint, body, {
    fetch: fetchOf(options),
    headers,
    label: "token endpoint",
  });
  return parseTokenResponse(answer);
}
