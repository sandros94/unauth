import type { ParseType } from "../../../../types";

export interface BuildOAuthDiscoveryArgs {
  /**
   * An optional base for all endpoint URLs.
   *
   * @default undefined
   * @example
   * "/oauth/v1"
   * "${issuer}/oauth/${jwks_uri|token_endpoint|introspection_endpoint|authorization_endpoint}"
   */
  base?: string;
  jwks_uri?: string;
  authorization_endpoint?: string;
  token_endpoint?: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
  scopes_supported?: string[];
  default_scope?: string;
  response_types_supported?: string[];
}

export type OAuthDiscoveryDocument<
  T extends Record<string, unknown> = Record<string, unknown>,
> = ParseType<
  Required<
    Omit<
      BuildOAuthDiscoveryArgs,
      "default_scope" | "revocation_endpoint" | "base"
    >
  > & {
    issuer: string;
    default_scope?: string;
    revocation_endpoint?: string;
  }
> &
  T;

export function buildOAuthDiscoveryDocument(
  options: BuildOAuthDiscoveryArgs & {
    issuer: string;
  },
): OAuthDiscoveryDocument {
  const { issuer, base, ...opts } = options;

  const baseUrl = `${issuer.replace(/\/+$/, "")}${
    base ? `/${base.replace(/^\/+|\/+$/g, "")}` : ""
  }`;

  return {
    ...opts,
    issuer: baseUrl,
    jwks_uri: opts.jwks_uri || `${baseUrl}/.well-known/jwks.json`,
    authorization_endpoint:
      opts.authorization_endpoint || `${baseUrl}/authorize`,
    token_endpoint: opts.token_endpoint || `${baseUrl}/token`,
    introspection_endpoint:
      opts.introspection_endpoint || `${baseUrl}/introspect`,
    revocation_endpoint: opts.revocation_endpoint,
    response_types_supported: ["code"], // only "code" is supported
    scopes_supported: opts.scopes_supported ?? [],
    default_scope: opts.default_scope,
  };
}
