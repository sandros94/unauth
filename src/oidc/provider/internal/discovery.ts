import type { ParseType } from "../../../types";

import {
  type OAuthDiscoveryOptions,
  buildOAuthDiscoveryDocument,
} from "../../../oauth/provider/internal";

export interface OIDCDiscoveryOptions extends OAuthDiscoveryOptions {
  userinfo_endpoint?: string;
  subject_types_supported?: string[];
  claims_supported?: string[];
}

export type OIDCDiscoveryDocument = ParseType<
  Required<
    Omit<
      OIDCDiscoveryOptions,
      "default_scope" | "revocation_endpoint" | "prefix"
    >
  > & {
    default_scope?: string;
    revocation_endpoint?: string;
  }
>;

/**
 * Build a minimal OpenID Provider Configuration (discovery) document.
 */
export function buildOIDCDiscoveryDocument(
  opts: OIDCDiscoveryOptions,
): OIDCDiscoveryDocument {
  const baseUrl = `${opts.issuer.replace(/\/+$/, "")}${
    opts.prefix ? `/${opts.prefix.replace(/^\/+|\/+$/g, "")}` : ""
  }`;
  const oauthDocument = buildOAuthDiscoveryDocument(opts);
  return {
    ...oauthDocument,
    userinfo_endpoint: opts.userinfo_endpoint || `${baseUrl}/userinfo`,
    subject_types_supported: opts.subject_types_supported ?? ["public"],
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
