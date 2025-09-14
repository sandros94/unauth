import type { ParseType } from "../../../types";

export interface OAuthDiscoveryOptions {
  issuer: string;
  /**
   * An optional prefix for all endpoint URLs.
   *
   * @default undefined
   * @example
   * "/oauth/v1"
   * "${issuer}/oauth/${jwks_uri|token_endpoint|introspection_endpoint|authorization_endpoint}"
   */
  prefix?: string;
  jwks_uri?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
  scopes_supported?: string[];
  default_scope?: string;
  response_types_supported?: string[];
}

export type OAuthDiscoveryDocument = ParseType<
  Required<
    Omit<
      OAuthDiscoveryOptions,
      "default_scope" | "revocation_endpoint" | "prefix"
    >
  > & {
    default_scope?: string;
    revocation_endpoint?: string;
  }
>;

export function buildOAuthDiscoveryDocument(
  opts: OAuthDiscoveryOptions,
): OAuthDiscoveryDocument {
  const baseUrl = `${opts.issuer.replace(/\/+$/, "")}${
    opts.prefix ? `/${opts.prefix.replace(/^\/+|\/+$/g, "")}` : ""
  }`;

  return {
    issuer: opts.issuer,
    jwks_uri: opts.jwks_uri || `${baseUrl}/.well-known/jwks.json`,
    authorization_endpoint:
      opts.authorization_endpoint || `${baseUrl}/authorize`,
    token_endpoint: opts.token_endpoint || `${baseUrl}/token`,
    introspection_endpoint:
      opts.introspection_endpoint || `${baseUrl}/introspect`,
    revocation_endpoint: opts.revocation_endpoint,
    response_types_supported: opts.response_types_supported ?? ["code"],
    scopes_supported: opts.scopes_supported ?? [],
    default_scope: opts.default_scope,
  };
}
