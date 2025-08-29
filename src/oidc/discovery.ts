import type { OIDCDiscoveryOptions } from "./types";

/**
 * Build a minimal OpenID Provider Configuration (discovery) document.
 */
export function buildDiscoveryDocument(
  opts: OIDCDiscoveryOptions,
): Record<string, unknown> {
  return {
    issuer: opts.issuer,
    authorization_endpoint: opts.authorization_endpoint,
    token_endpoint: opts.token_endpoint,
    userinfo_endpoint: opts.userinfo_endpoint,
    jwks_uri: opts.jwks_uri,
    response_types_supported: opts.response_types_supported ?? [
      "code",
      "id_token",
      "code id_token",
    ],
    subject_types_supported: opts.subject_types_supported ?? ["public"],
    id_token_signing_alg_values_supported:
      opts.id_token_signing_alg_values_supported ?? ["RS256"],
    scopes_supported: opts.scopes_supported ?? [
      "openid",
      "profile",
      "email",
      "phone",
      "address",
      "offline_access",
    ],
    claims_supported: opts.claims_supported ?? [
      "aud",
      "exp",
      "iat",
      "iss",
      "sub",
      "auth_time",
      "acr",
      "amr",
      "azp",
      "nonce",
      "at_hash",
      "c_hash",
      "name",
      "given_name",
      "family_name",
      "preferred_username",
      "email",
      "email_verified",
      "picture",
    ],
  };
}
