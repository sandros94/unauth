import {
  type AuthorizeErrorResponse,
  type AuthorizeRequest as OAuthAuthorizeRequest,
  type BuildAuthorizationCodeArgs as OAuthBuildAuthorizationCodeArgs,
  type BuildAuthorizationCodeReturn as OAuthBuildAuthorizationCodeReturn,
  buildAuthorizationCode as oauthBuildAuthorizationCode,
  buildAuthorizationRedirect,
  OAuthError,
} from "../../../oauth";

export {
  type BuildAuthorizationRedirectArgs,
  validateRedirectUri,
  buildAuthorizationRedirect,
} from "../../../oauth/provider/internal/authorize";

// #region type definitions

export interface AuthorizeRequest extends OAuthAuthorizeRequest {
  /**
   * Scope MUST include "openid"
   */
  scope: string;
  /**
   * Nonce value to associate a client session with an ID token, and to mitigate replay attacks.
   */
  nonce?: string;
  /**
   * PKCE code challenge method MUST be S256 (SHA-256)
   */
  code_challenge_method: "S256";
}

export interface BuildAuthorizationCodeArgs
  extends Omit<OAuthBuildAuthorizationCodeArgs, "req"> {
  req: AuthorizeRequest;
}

export type BuildAuthorizationCodeReturn = OAuthBuildAuthorizationCodeReturn;

// #endregion type definitions

// #region validation helpers

function scopeIncludesOpenId(scope: unknown): boolean {
  if (typeof scope !== "string") return false;
  return scope.split(/\s+/).includes("openid");
}

// #endregion validation helpers

// #region runtime functions

/**
 * Build an OAuth 2.1 authorization code with OIDC requirements:
 * - scope MUST include "openid"
 * - nonce if present must be propagated
 * - code_challenge_method MUST be "S256"
 */
export async function buildAuthorizationCode(
  args: BuildAuthorizationCodeArgs,
): Promise<BuildAuthorizationCodeReturn> {
  const { req, claims, iss, randomJti, options } = args;

  // Enforce OIDC-specific inputs
  let error: AuthorizeErrorResponse | undefined = undefined;

  if (!scopeIncludesOpenId(req.scope)) {
    error = new OAuthError({
      error: "invalid_request",
      error_description: "Missing required openid scope",
      state: req.state,
      iss,
    }).toJSON();
  }

  if (req.code_challenge_method !== "S256") {
    error = new OAuthError({
      error: "invalid_request",
      error_description: "code_challenge_method must be S256",
      state: req.state,
      iss,
    }).toJSON();
  }

  // if error, return early
  if (error) {
    return buildAuthorizationRedirect({
      res: error,
      redirect_uri: req.redirect_uri,
    });
  }

  // Propagate nonce via claims so it is available to the token step
  const enrichedClaims = {
    ...claims,
    ...(req.nonce ? { nonce: req.nonce } : {}),
  };

  return oauthBuildAuthorizationCode({
    req,
    claims: enrichedClaims,
    iss,
    randomJti,
    options,
  });
}

// #endregion runtime functions
