import type { ParseType } from "../../../../types";

import {
  type BuildOAuthDiscoveryArgs,
  buildOAuthDiscoveryDocument,
} from "../../../oauth/provider/internal";

export interface BuildOIDCDiscoveryArgs extends BuildOAuthDiscoveryArgs {
  userinfo_endpoint?: string;
  subject_types_supported?: string[];
  claims_supported?: string[];
}

export type OIDCDiscoveryDocument = ParseType<
  Required<
    Omit<
      BuildOIDCDiscoveryArgs,
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
  opts: BuildOIDCDiscoveryArgs,
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
    ],
    claims_supported: opts.claims_supported ?? [
      "aud",
      "exp",
      "iat",
      "iss",
      "sub",
      "nonce",
      "at_hash",
      "name",
      "given_name",
      "family_name",
      "preferred_username",
      "email",
      "email_verified",
      "picture",
      // "auth_time", // authentication logging is not currently tracked
    ],
  };
}
