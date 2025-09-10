import { encrypt } from "unjwt/jwe";

import type { AuthorizationCodeClaims } from "../types";
import type { OnAuthorizationCodeReqReturn } from "../hooks";

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
   * If multiple redirect_uris are registered for the client, the original request must contain a valid redirect_uri. Otherwise, if only one is registered, the client's default can be used.
   */
  redirect_uri: string;
  /**
   * An opaque value used by the client to maintain state between the request and callback. The authorization server includes this value when redirecting the user agent back to the client.
   */
  state?: string;
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
  claims: AuthorizationCodeClaims;
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

export function validateAuthorizationCodeRequest(
  oauthReq: AuthorizationCodeRequest,
  options: Pick<ResolvedOAuthOptions, "issuer" | "defaultCodeChallengeMethod">,
): AuthorizationErrorResponse | undefined {
  const { issuer: iss, defaultCodeChallengeMethod } = options;
  const state = oauthReq.state;

  if (!isAuthorizationCodeRequest(oauthReq)) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Invalid authorize request",
      state,
      iss,
    }).toJSON();
  }

  if (oauthReq.response_type !== "code") {
    return new OAuthError({
      error: "unsupported_response_type",
      error_description: `Unsupported response_type: ${oauthReq.response_type}`,
      state,
      iss,
    }).toJSON();
    // TODO: allow custom response_type extensions?
  }

  // PKCE: Required for code flow
  if (!oauthReq.code_challenge) {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Missing code_challenge (PKCE)",
      state,
      iss,
    }).toJSON();
  }

  const m = oauthReq.code_challenge_method || defaultCodeChallengeMethod;
  if (m !== "plain" && m !== "S256") {
    return new OAuthError({
      error: "invalid_request",
      error_description: "Unsupported code_challenge_method",
      state,
      iss,
    }).toJSON();
  }

  return undefined;
}

export async function buildAuthorizationCode(
  onAuthCodeReturn: OnAuthorizationCodeReqReturn,
  options: ResolvedOAuthOptions,
): Promise<AuthorizationCodeReturn | AuthorizationErrorResponse> {
  const {
    issuer: iss,
    randomJti,
    defaultCodeChallengeMethod,
    authorizationCode,
  } = options;
  const { claims: extraClaims, ...oauthReq } = onAuthCodeReturn;

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
  const claims: AuthorizationCodeClaims = {
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

  await options.hooks?.onAuthorizationCodeIssued?.({ claims });

  return { code, state, iss, claims };
}

/**
 * Build redirect URI with either ?code= or ?error= fragment/query params as per OAuth 2.1
 * Note: OAuth 2.1 uses query component for authorization code; we preserve given state.
 */
export function buildAuthorizationRedirect(
  request: AuthorizationCodeRequest,
  result: AuthorizationCodeResponse | AuthorizationErrorResponse,
  options: Pick<ResolvedOAuthOptions, "issuer">,
): string | AuthorizationErrorResponse {
  const url = new URL(request.redirect_uri);
  const params = url.searchParams;
  params.set("iss", options.issuer);

  if (!("code" in result) && !("error" in result)) {
    return new OAuthError({
      error: "server_error",
      error_description: "Invalid authorization result",
      iss: options.issuer,
    }).toJSON();
  } else if ("code" in result) {
    params.set("code", result.code);
    if (result.state) params.set("state", result.state);
  } else {
    params.set("error", result.error);
    if (result.error_description)
      params.set("error_description", result.error_description);
    if (result.state) params.set("state", result.state);
  }

  url.search = params.toString();
  return url.toString();
}

// --- Main Public API ---

export async function issueAuthorizationCode(
  options: ResolvedOAuthOptions,
): Promise<string | AuthorizationErrorResponse> {
  const { issuer: iss, defaultCodeChallengeMethod } = options;

  if (!options.hooks?.onAuthorizeRequest) {
    throw new OAuthError({
      error: "server_error",
      error_description: "Missing onAuthorizeReq hook",
      iss,
    });
  }

  let onAuthRes: OnAuthorizationCodeReqReturn | undefined = undefined;
  try {
    onAuthRes = await options.hooks.onAuthorizeRequest({
      issuer: iss,
      defaultCodeChallengeMethod,
    });
  } catch (error_: unknown) {
    return error_ instanceof OAuthError
      ? new OAuthError({
          ...error_.toJSON(),
          iss: error_.iss || iss,
        }).toJSON()
      : new OAuthError({
          error: "server_error",
          error_description: "Error in authorization callback",
          iss,
          cause: error_,
        }).toJSON();
  }

  if (!onAuthRes || !onAuthRes.redirect_uri) {
    return new OAuthError({
      error: "invalid_request",
      error_description:
        "redirect_uri is missing and no registered redirect URI is available for this client",
      state: onAuthRes?.state,
      iss,
    }).toJSON();
  }

  const validatedRes = validateAuthorizationCodeRequest(onAuthRes, {
    issuer: iss,
    defaultCodeChallengeMethod,
  });

  return buildAuthorizationRedirect(
    onAuthRes,
    validatedRes || (await buildAuthorizationCode(onAuthRes, options)),
    options,
  );
}
