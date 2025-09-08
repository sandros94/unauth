import type { JWTClaims } from "unjwt";
import { encrypt } from "unjwt/jwe";

import type { MaybePromise } from "../../types";
import type { OAuthAuthorizationCodeClaims } from "../types";

import { type AuthorizationErrorResponse, OAuthError } from "./error";
import type { ResolvedOAuthOptions } from "./defaults";

/**
 * OAuth 2.1 Authorization Endpoint utilities
 * These helpers validate the authorization request, enforce PKCE, build the authorization code (JWE), and craft redirect URIs with code or error responses.
 */

export type OAuthResponseType = "code";

export interface AuthorizationCodeRequest {
  client_id: string;
  /**
   * only "code" (implicit removed by OAuth 2.1), other may be added by extensions (unordered, space delimited)
   */
  response_type: OAuthResponseType | (string & {});
  /**
   * The code challenge for PKCE.
   */
  code_challenge: string;
  /**
   * An opaque value used by the client to maintain state between the request and callback. The authorization server includes this value when redirecting the user agent back to the client.
   */
  state?: string;
  /**
   * OPTIONAL if only one redirect URI is registered for this client. REQUIRED if multiple redirect URIs are registered for this client.
   */
  redirect_uri?: string;
  /**
   * The requested scope, space-delimited.
   */
  scope?: string;
  /**
   * Resource Indicators (RFC 8707). Can be provided multiple times or as a space-delimited list by clients; here we accept string or array.
   * These will be mapped to the Access Token audience (aud) during token issuance.
   */
  resource?: string | string[];
  /**
   * The code challenge method for PKCE.
   * Must be either "S256" or "plain".
   *
   * @default "plain"
   */
  code_challenge_method?: "S256" | "plain";
  [key: string]: unknown;
  // TODO: OIDC prompt/login_hint etc are out-of-scope for plain OAuth 2.1, but could be added by callers
}

export type OAuthAuthorizationCallback = (
  opts: Pick<
    ResolvedOAuthOptions,
    "issuer" | "defaultCodeChallengeMethod" | "authorizationCode"
  >,
) => MaybePromise<
  AuthorizationCodeRequest & { claims: JWTClaims & { sub: string } }
>;

export interface AuthorizationCodeResponse {
  /**
   * The authorization code (JWE) to be returned to the client.
   */
  code: string;
  /**
   * An opaque value used by the client to maintain state between the request and callback. The authorization server includes this value when redirecting the user agent back to the client.
   */
  state?: string;
  /**
   * The identifier of the authorization server which the client can use to prevent mix-up attacks, if the client interacts with more than one authorization server.
   */
  iss?: string;
}

export interface AuthorizationCodeReturn extends AuthorizationCodeResponse {
  iss: Exclude<AuthorizationCodeResponse["iss"], undefined>;
  claims: OAuthAuthorizationCodeClaims;
}

export function isAuthorizationCodeRequest(
  value: unknown,
): value is AuthorizationCodeRequest {
  if (typeof value !== "object" || value == null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.client_id === "string" &&
    typeof v.response_type === "string" &&
    typeof v.code_challenge === "string" &&
    (v.redirect_uri === undefined || typeof v.redirect_uri === "string") &&
    (v.state === undefined || typeof v.state === "string") &&
    (v.scope === undefined || typeof v.scope === "string")
  );
}

export function validateAuthorizationCodeRequest<
  T extends AuthorizationCodeRequest,
>(
  oauthReq: T,
  options: Pick<ResolvedOAuthOptions, "issuer" | "defaultCodeChallengeMethod">,
): T {
  const { issuer: iss, defaultCodeChallengeMethod } = options;
  const state = oauthReq.state;

  if (!isAuthorizationCodeRequest(oauthReq)) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Invalid authorize request",
      state,
      iss,
    });
  }

  if (oauthReq.response_type !== "code") {
    throw new OAuthError({
      error: "unsupported_response_type",
      error_description: `Unsupported response_type: ${oauthReq.response_type}`,
      state,
      iss,
    });
    // TODO: allow custom response_type extensions?
  }

  // PKCE: Required for code flow
  if (!oauthReq.code_challenge) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing code_challenge (PKCE)",
      state,
      iss,
    });
  }

  const m = oauthReq.code_challenge_method || defaultCodeChallengeMethod;
  if (m !== "plain" && m !== "S256") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Unsupported code_challenge_method",
      state,
      iss,
    });
  }

  return oauthReq;
}

export async function buildAuthorizationCode(
  options: ResolvedOAuthOptions,
  cb: OAuthAuthorizationCallback,
): Promise<AuthorizationCodeReturn | AuthorizationErrorResponse> {
  const {
    issuer: iss,
    randomJti,
    defaultCodeChallengeMethod,
    authorizationCode,
  } = options;

  let extraClaims: JWTClaims & { sub: string };
  let oauthReq: AuthorizationCodeRequest;

  try {
    const result = await cb({
      issuer: iss,
      defaultCodeChallengeMethod,
      authorizationCode,
    });
    const { claims, ...rest } = result;
    extraClaims = claims;
    oauthReq = rest as AuthorizationCodeRequest;
  } catch (error_: unknown) {
    if (error_ instanceof OAuthError) return error_.toJSON();
    throw new OAuthError({
      error: "server_error",
      error_description: "Error in authorization callback",
      state: (error_ as OAuthError)?.state || undefined,
      iss,
      cause: error_,
    });
  }

  const state = oauthReq.state;
  if (
    !("sub" in extraClaims) ||
    typeof extraClaims.sub !== "string" ||
    !extraClaims.sub
  ) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Missing subject (sub) for end-user in authorization",
      state,
      iss,
    }).toJSON();
  }

  // Code challenge method
  const m = oauthReq.code_challenge_method || defaultCodeChallengeMethod;

  const iat = Math.floor(
    authorizationCode.encryptOptions.currentDate.getTime() / 1000,
  );
  const claims: OAuthAuthorizationCodeClaims = {
    jti: randomJti(),
    ...(oauthReq.redirect_uri ? { redirect_uri: oauthReq.redirect_uri } : {}),
    ...extraClaims,
    iss,
    iat,
    exp: iat + authorizationCode.encryptOptions.expiresIn,
    client_id: oauthReq.client_id,
    code_challenge: oauthReq.code_challenge,
    code_challenge_method: m,
    // Persist resource indicators so the token endpoint can translate them to aud
    ...(oauthReq.resource ? { resource: oauthReq.resource } : {}),
    ...(oauthReq.scope ? { scope: oauthReq.scope } : {}),
  };

  const code = await encrypt(
    claims,
    authorizationCode.privateKey,
    authorizationCode.encryptOptions,
  );
  return { code, state, iss, claims };
}

/**
 * Build redirect URI with either ?code= or ?error= fragment/query params as per OAuth 2.1
 * Note: OAuth 2.1 uses query component for authorization code; we preserve given state.
 */
export function buildAuthorizationRedirect<T extends string | URL>(
  iss: string,
  redirectUri: T,
  result: AuthorizationCodeResponse | AuthorizationErrorResponse,
): T {
  const url = redirectUri instanceof URL ? redirectUri : new URL(redirectUri);
  const params = url.searchParams;
  params.set("iss", iss);
  if ("code" in result) {
    params.set("code", result.code);
    if (result.state) params.set("state", result.state); // TODO: URI encode?
  } else {
    params.set("error", result.error);
    if (result.error_description)
      params.set("error_description", result.error_description); // TODO: URI encode?
    if (result.state) params.set("state", result.state);
  }
  url.search = params.toString();
  return (redirectUri instanceof URL ? url : url.toString()) as T;
}
