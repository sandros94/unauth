import type { ParseType } from "../types";

export interface OAuthDiscoveryOptions {
  issuer: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  jwks_uri?: string;
  introspection_endpoint?: string;
  scopes_supported?: string[];
  default_scope?: string;
  response_types_supported?: string[];
}

export type OAuthDiscoveryDocument = ParseType<
  Required<Omit<OAuthDiscoveryOptions, "default_scope">> & {
    default_scope?: string;
  }
>;

export function buildDiscoveryDocument(
  opts: OAuthDiscoveryOptions,
): OAuthDiscoveryDocument {
  const issuer = opts.issuer.replace(/\/+$/, "");
  return {
    issuer,
    jwks_uri: opts.jwks_uri || `${issuer}/.well-known/jwks.json`,
    authorization_endpoint: opts.authorization_endpoint || `${issuer}/authorize`,
    token_endpoint: opts.token_endpoint || `${issuer}/token`,
    introspection_endpoint: opts.introspection_endpoint || `${issuer}/introspect`,
    response_types_supported: opts.response_types_supported ?? ["code"],
    scopes_supported: opts.scopes_supported ?? [],
    default_scope: opts.default_scope,
  };
}
