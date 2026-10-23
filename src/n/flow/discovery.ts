import {
  type Fetch,
  assertSecureUrl,
  configError,
  fetchOf,
  nowOf,
  providerError,
  stringField,
} from "./_http.ts";
import type { CacheDriver } from "./_cache.ts";
import { assertIssuerDocument, defineMetadataLoader, requiredMember } from "./_metadata.ts";
import { assertProvider } from "./provider.ts";
import type { OAuthProvider } from "./types.ts";

/** The OpenID Provider metadata a flow uses (OpenID Connect Discovery 1.0 §3). */
export interface OidcMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint?: string;
  [member: string]: unknown;
}

/** Options of {@link discover} and {@link resolveProvider}. */
export interface DiscoverOptions {
  fetch?: Fetch;
  now?: () => number;
  /** Fetch again even when the cached document is fresh. */
  force?: boolean;
  /** Keep the document here instead of in memory. */
  cache?: CacheDriver;
  /**
   * Development only: hosts whose issuer may use plain `http:` (see `OAuthProvider.insecureHosts`).
   * `resolveProvider` uses the provider's own list instead.
   */
  insecureHosts?: string[];
}

const LABEL = "discovery document";

const load = /* @__PURE__ */ defineMetadataLoader<OidcMetadata>({
  name: "discovery",
  label: LABEL,
  url: metadataUrl,
  parse: parseMetadata,
});

/**
 * Reads `${issuer}/.well-known/openid-configuration`, kept for ten minutes per issuer: in memory
 * per injected `fetch`, or in `options.cache`.
 * The issuer must be `https:` (or `http:` on localhost or a host in `insecureHosts`) and the
 * document must name it exactly (Discovery §4.3); anything else throws `ERR_AUTHN_PROVIDER_ERROR`,
 * rethrown without a fetch for five seconds. `force` refetches a fresh document, not a failed one.
 */
export async function discover(issuer: string, options?: DiscoverOptions): Promise<OidcMetadata> {
  assertSecureUrl(issuer, {
    label: "The OpenID Connect issuer",
    insecureHosts: options?.insecureHosts,
  });
  return load(issuer, {
    fetch: fetchOf(options),
    now: nowOf(options),
    cache: options?.cache,
    force: options?.force,
  });
}

/**
 * The provider with concrete endpoints: a `discovery` provider gets the ones it leaves unset from
 * its issuer's metadata (see {@link discover}), and `issuerParameter` when the metadata advertises
 * `authorization_response_iss_parameter_supported`; any other provider is returned as is.
 */
export async function resolveProvider<TProfile>(
  provider: OAuthProvider<TProfile>,
  options?: DiscoverOptions,
): Promise<OAuthProvider<TProfile>> {
  if (!provider.discovery) return provider;
  if (!provider.issuer)
    throw configError(
      `OAuthProvider ${JSON.stringify(provider.id)} needs an "issuer" for discovery.`,
    );
  const metadata = await discover(provider.issuer, {
    ...options,
    insecureHosts: provider.insecureHosts,
  });
  const resolved: OAuthProvider<TProfile> = {
    ...provider,
    discovery: false,
    authorization: provider.authorization ?? metadata.authorization_endpoint,
    token: provider.token ?? metadata.token_endpoint,
    userinfo: provider.userinfo ?? metadata.userinfo_endpoint,
    jwks: provider.jwks ?? metadata.jwks_uri,
  };
  if (
    resolved.issuerParameter === undefined &&
    metadata.authorization_response_iss_parameter_supported === true
  ) {
    resolved.issuerParameter = true;
  }
  try {
    assertProvider(resolved);
  } catch (error) {
    throw providerError(`The discovery document of ${provider.issuer} names unusable endpoints.`, {
      reason: "malformed",
      cause: error,
    });
  }
  return resolved;
}

/** The metadata `document` holds for `issuer`; `ERR_AUTHN_PROVIDER_ERROR` when it names another or lacks an endpoint. */
function parseMetadata(document: unknown, issuer: string): OidcMetadata {
  const context = { issuer, url: metadataUrl(issuer), label: LABEL };
  const metadata = assertIssuerDocument(document, context);
  const endpoint = (name: string): string => requiredMember(metadata, name, context);
  return {
    ...metadata,
    issuer,
    authorization_endpoint: endpoint("authorization_endpoint"),
    token_endpoint: endpoint("token_endpoint"),
    jwks_uri: endpoint("jwks_uri"),
    userinfo_endpoint: stringField(metadata, "userinfo_endpoint"),
  };
}

function metadataUrl(issuer: string): string {
  return `${issuer.replace(/\/$/, "")}/.well-known/openid-configuration`;
}
