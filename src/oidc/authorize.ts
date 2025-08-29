import type { OAuthAuthorizeRequest } from "../oauth/authorize";

/**
 * Extend OAuth authorize request with OIDC parameters.
 */
export interface OIDCAuthorizeRequest extends OAuthAuthorizeRequest {
  scope?: string; // must include openid
  nonce?: string;
  prompt?: string;
  login_hint?: string;
  display?: string;
  max_age?: string | number;
  ui_locales?: string;
  id_token_hint?: string;
  acr_values?: string;
  response_mode?: "query" | "fragment" | "form_post";
}

/**
 * Validate that the request is an OIDC authentication request (scope includes openid) based on OAuth 2.1
 */
export function validateOIDCAuthorizeRequest(req: OIDCAuthorizeRequest): void {
  const scope = (req.scope || "").split(/\s+/g);
  if (!scope.includes("openid")) {
    throw new Error("[OIDC] Missing required openid scope");
  }

  // Enforce OAuth 2.1 compatible behavior only:
  // - Only response_type=code is supported (no implicit or hybrid flows)
  if (req.response_type && req.response_type !== "code") {
    throw new Error(
      "[OIDC] Unsupported response_type for OAuth 2.1 (only code)",
    );
  }
  // - Only response_mode=query is compatible with pure authorization code (others require implicit/hybrid handling)
  if (req.response_mode && req.response_mode !== "query") {
    throw new Error(
      "[OIDC] Unsupported response_mode for OAuth 2.1 (only query with code)",
    );
  }
  // nonce is not required for code flow.
}
