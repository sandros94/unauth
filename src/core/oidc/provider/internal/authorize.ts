import {
  type AuthorizeRequest,
  type Result,
  type Success,
  type Failure,
  type AuthorizeErrorResponse,
  type AuthorizationCodeClaims,
  type NormalizedAuthorizeInput as OAuthNormalizedAuthorizeInput,
  type IssueAuthorizationCodeOptions,
  OAuthError,
  validateAuthorizeRequest as oauthValidateAuthorizeRequest,
  buildAuthorizationRedirect as oauthBuildAuthorizationRedirect,
  issueAuthorizationCode as oauthIssueAuthorizationCode,
} from "../../../oauth";

export {
  type IssueAuthorizationCodeOptions,
  validateRedirectUri,
  buildAuthorizationRedirect,
} from "../../../oauth/provider/internal/authorize";

// #region types

export interface NormalizedAuthorizeInput
  extends Omit<
    OAuthNormalizedAuthorizeInput,
    "scope" | "code_challenge_method"
  > {
  /**
   * Scope MUST include "openid"
   */
  scope: string;
  /**
   * PKCE code challenge method MUST be S256 (SHA-256)
   */
  code_challenge_method: "S256";
  /**
   * Nonce value to associate a client session with an ID token, and to mitigate replay attacks.
   */
  nonce?: string;
}

export type IssueAuthorizationCodeReturn = Result<
  string,
  AuthorizationCodeClaims,
  AuthorizeErrorResponse
>;

// #endregion types

// #region internals

function scopeIncludesOpenId(scope: unknown): boolean {
  if (typeof scope !== "string") return false;
  return scope.split(/\s+/).includes("openid");
}

// #endregion internals

// #region validations

export function validateAuthorizeRequest(
  req: AuthorizeRequest,
  errorDetails?: Omit<AuthorizeErrorResponse, "error" | "error_description">,
): Result<
  Omit<NormalizedAuthorizeInput, "subject" | "redirect_uri"> & {
    redirect_uri?: string;
  },
  undefined,
  AuthorizeErrorResponse
> {
  if (!req.scope || !scopeIncludesOpenId(req.scope)) {
    return {
      success: false,
      error: new OAuthError({
        error: "invalid_request",
        error_description: "Missing required openid scope",
        state: req.state || errorDetails?.state,
        iss: errorDetails?.iss,
      }).toJSON(),
    };
  }

  if (req.code_challenge_method !== "S256") {
    return {
      success: false,
      error: new OAuthError({
        error: "invalid_request",
        error_description: "code_challenge_method must be S256",
        state: req.state || errorDetails?.state,
        iss: errorDetails?.iss,
      }).toJSON(),
    };
  }

  const result = oauthValidateAuthorizeRequest(req, errorDetails);

  return result.success
    ? {
        success: true,
        value: {
          ...result.value,
          code_challenge_method: req.code_challenge_method,
          scope: req.scope,
          nonce: req.nonce,
        },
      }
    : result;
}

// #endregion validations

// #region runtime

/**
 * Build an OAuth 2.1 authorization code with OIDC requirements:
 * - scope MUST include "openid"
 * - nonce if present must be propagated
 * - code_challenge_method MUST be "S256"
 */
export async function issueAuthorizationCode(
  args: NormalizedAuthorizeInput,
  options: IssueAuthorizationCodeOptions,
): Promise<IssueAuthorizationCodeReturn> {
  // Enforce OIDC-specific inputs
  let error: AuthorizeErrorResponse | undefined = undefined;

  if (!scopeIncludesOpenId(args.scope)) {
    error = new OAuthError({
      error: "invalid_request",
      error_description: "Missing required openid scope",
      state: args.state,
      iss: options.iss,
    }).toJSON();
  }

  if (args.code_challenge_method !== "S256") {
    error = new OAuthError({
      error: "invalid_request",
      error_description: "code_challenge_method must be S256",
      state: args.state,
      iss: options.iss,
    }).toJSON();
  }

  // if error, return early
  if (error) {
    return oauthBuildAuthorizationRedirect(
      args.redirect_uri,
      undefined,
      error,
      options.iss,
      args.state,
    ) as
      | Success<string, undefined, AuthorizeErrorResponse>
      | Failure<AuthorizeErrorResponse>;
  }

  // Propagate nonce via claims so it is available to the token step
  const acExtraClaims = {
    ...args.acExtraClaims,
    ...(args.nonce ? { nonce: args.nonce } : {}),
  };

  return oauthIssueAuthorizationCode(
    {
      ...args,
      acExtraClaims,
    },
    options,
  );
}

// #endregion runtime
