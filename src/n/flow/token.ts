import { type Fetch, configError, fetchOf, nowOf } from "./_http.ts";
import { postForm } from "./_http-json.ts";
import { authenticateClient } from "./_client-auth.ts";
import { parseTokenResponse } from "./_token-response.ts";
import type { OAuthTokens, OAuthProvider } from "./types.ts";

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
  fetch?: Fetch;
  now?: () => number;
}

/**
 * Trades a refresh token for new tokens (RFC 6749 §6); the old refresh token is kept when the
 * provider does not rotate it. A refusal or an unusable body throws `ERR_AUTHN_TOKEN_EXCHANGE`
 * (401); an endpoint that gives no answer throws `ERR_AUTHN_PROVIDER_ERROR` (502).
 */
export async function refreshTokens(
  provider: OAuthProvider<unknown>,
  options: RefreshTokensOptions,
): Promise<OAuthTokens> {
  const body = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: options.refreshToken,
  });
  if (options.scopes) body.set("scope", options.scopes.join(provider.scopeSeparator));
  const tokens = await tokenRequest(provider, body, options);
  return { ...tokens, refresh_token: tokens.refresh_token ?? options.refreshToken };
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
