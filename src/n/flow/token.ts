import { UnauthError } from "../../_internal/error.ts";
import { type Fetch, configError, fetchOf, nowOf, readObject, stringField } from "./_http.ts";
import { authenticateClient } from "./_client-auth.ts";
import type { OAuthTokens, Provider } from "./types.ts";

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
 * carrying `error`, and any other failure throw `ERR_AUTHN_TOKEN_EXCHANGE` (401) with the
 * provider's error in `cause`.
 */
export function exchangeCode(
  provider: Provider<unknown>,
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
 * Trades a refresh token for new tokens (RFC 6749 §6). The old refresh token is kept when the
 * provider does not rotate it. Failures throw `ERR_AUTHN_TOKEN_EXCHANGE`.
 */
export async function refreshTokens(
  provider: Provider<unknown>,
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
  provider: Provider<unknown>,
  body: URLSearchParams,
  options: { fetch?: Fetch; now?: () => number },
): Promise<OAuthTokens> {
  const endpoint = provider.token;
  if (!endpoint) {
    throw configError(
      `Provider ${JSON.stringify(provider.id)} has no "token" endpoint yet; pass it through resolveProvider() first.`,
    );
  }
  for (const [name, value] of Object.entries(provider.tokenParams)) {
    if (!body.has(name)) body.set(name, value);
  }
  const headers = new Headers({
    "accept": "application/json",
    "content-type": "application/x-www-form-urlencoded",
  });
  await authenticateClient(provider, { body, headers, endpoint, now: nowOf(options) });

  let response: Response;
  try {
    response = await fetchOf(options)(endpoint, { method: "POST", headers, body });
  } catch (error) {
    throw exchangeError("Could not reach the token endpoint.", { cause: error });
  }
  const answer = await readObject(response);
  if ("tooLarge" in answer) {
    throw exchangeError(
      `The token endpoint answered more than the ${answer.tooLarge} bytes allowed.`,
      { reason: "too-large", status: response.status },
    );
  }
  const raw = answer.object;
  const error = stringField(raw, "error");
  if (error !== undefined) {
    throw exchangeError("The token endpoint refused the grant.", {
      status: response.status,
      error,
      error_description: stringField(raw, "error_description"),
      error_uri: stringField(raw, "error_uri"),
    });
  }
  if (!response.ok || !raw) {
    throw exchangeError(`The token endpoint answered ${response.status}.`, {
      status: response.status,
    });
  }
  return parseTokens(raw);
}

function parseTokens(raw: Record<string, unknown>): OAuthTokens {
  const access_token = stringField(raw, "access_token");
  const token_type = stringField(raw, "token_type");
  if (access_token === undefined || token_type === undefined) {
    throw exchangeError("The token endpoint answered without an access_token and token_type.", {});
  }
  if (token_type.toLowerCase() !== "bearer") {
    throw exchangeError("The token endpoint issued a token type other than Bearer.", {
      token_type,
    });
  }
  const tokens: OAuthTokens = { access_token, token_type, raw };
  const expiresIn = numericField(raw.expires_in);
  if (expiresIn !== undefined) tokens.expires_in = expiresIn;
  const refreshToken = stringField(raw, "refresh_token");
  if (refreshToken !== undefined) tokens.refresh_token = refreshToken;
  const scope = stringField(raw, "scope");
  if (scope !== undefined) tokens.scope = scope;
  const idToken = stringField(raw, "id_token");
  if (idToken !== undefined) tokens.id_token = idToken;
  return tokens;
}

/** A finite number, or a string of digits; anything else is `undefined`. */
function numericField(value: unknown): number | undefined {
  if (typeof value === "number") return Number.isFinite(value) ? value : undefined;
  return typeof value === "string" && /^\d+$/.test(value) ? Number(value) : undefined;
}

function exchangeError(
  message: string,
  cause: Partial<{
    reason: "too-large";
    status: number;
    error: string;
    error_description: string;
    error_uri: string;
    token_type: string;
    cause: unknown;
  }>,
): UnauthError<"ERR_AUTHN_TOKEN_EXCHANGE"> {
  return new UnauthError(`[unauth/n] ${message}`, "ERR_AUTHN_TOKEN_EXCHANGE", {
    status: 401,
    cause,
  });
}
