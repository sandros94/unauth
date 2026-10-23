import { assertSecureUrl, configError } from "./_http.ts";
import type {
  CustomProvider,
  CustomProviderConfig,
  OAuthProvider,
  ProviderConfig,
  TokenAuthMethod,
} from "./types.ts";

/**
 * A provider from its descriptor, with secure defaults filled in: PKCE `S256`, a nonce for
 * OpenID Connect, `query` response mode, and the client authentication its credentials allow.
 * A `custom` descriptor is checked for its two legs. Throws `ERR_UNAUTH_CONFIG_INVALID` for a
 * descriptor that cannot work; performs no I/O.
 */
export function defineProvider<TProfile = Record<string, unknown>>(
  descriptor: ProviderConfig<TProfile>,
): OAuthProvider<TProfile>;
export function defineProvider<TProfile = Record<string, unknown>>(
  descriptor: CustomProviderConfig<TProfile>,
): CustomProvider<TProfile>;
export function defineProvider<TProfile>(
  descriptor: ProviderConfig<TProfile> | CustomProviderConfig<TProfile>,
): OAuthProvider<TProfile> | CustomProvider<TProfile> {
  if (descriptor.kind === "custom") {
    assertCustomProvider(descriptor);
    return { ...descriptor };
  }
  const { pkce = "S256", profile, ...rest } = descriptor;
  const provider: OAuthProvider<TProfile> = {
    ...rest,
    discovery: descriptor.discovery ?? false,
    scopes: descriptor.scopes ?? [],
    scopeSeparator: descriptor.scopeSeparator ?? " ",
    pkce: pkce === true ? "S256" : pkce,
    nonce: descriptor.nonce ?? descriptor.kind === "oidc",
    tokenAuth: descriptor.tokenAuth ?? defaultTokenAuth(descriptor.client),
    responseMode: descriptor.responseMode ?? "query",
    authorizationParams: descriptor.authorizationParams ?? {},
    tokenParams: descriptor.tokenParams ?? {},
    userinfoHeaders: descriptor.userinfoHeaders ?? {},
    profile: async (context) => profile(context),
  };
  assertProvider(provider);
  return provider;
}

/** Throws `ERR_UNAUTH_CONFIG_INVALID` unless `provider` can run a flow. */
export function assertProvider(provider: OAuthProvider<unknown>): void {
  const label = `Provider ${JSON.stringify(provider.id)}`;
  if (!provider.id) throw configError(`A provider needs a non-empty "id".`);
  if (!provider.client.id) throw configError(`${label} needs "client.id".`);

  for (const name of ["authorization", "token", "userinfo", "jwks", "issuer"] as const) {
    const value = provider[name];
    if (value !== undefined) {
      assertSecureUrl(value, {
        label: `${label} "${name}"`,
        insecureHosts: provider.insecureHosts,
      });
    }
  }
  if (provider.discovery || provider.kind === "oidc") {
    if (!provider.issuer) throw configError(`${label} needs an "issuer" for OpenID Connect.`);
  }
  if (!provider.discovery) {
    if (!provider.authorization) throw configError(`${label} needs an "authorization" endpoint.`);
    if (!provider.token) throw configError(`${label} needs a "token" endpoint.`);
    if (provider.kind === "oidc" && !provider.jwks) {
      throw configError(`${label} needs "jwks" or "discovery: true" to verify id_tokens.`);
    }
  }
  if (
    provider.kind === "oidc" &&
    provider.openidScope !== false &&
    !provider.scopes.includes("openid")
  ) {
    throw configError(
      `${label} is OpenID Connect and needs the "openid" scope (or "openidScope: false").`,
    );
  }
  if (provider.issuerParameter && !provider.issuer) {
    throw configError(`${label} needs an "issuer" to check the "iss" parameter.`);
  }

  const { tokenAuth, client } = provider;
  if ((tokenAuth === "basic" || tokenAuth === "body") && !client.secret) {
    throw configError(`${label} authenticates with "${tokenAuth}" and needs "client.secret".`);
  }
  if (tokenAuth === "private_key_jwt" && !client.privateKey) {
    throw configError(
      `${label} authenticates with "private_key_jwt" and needs "client.privateKey".`,
    );
  }
}

function assertCustomProvider(provider: CustomProvider<unknown>): void {
  if (!provider.id) throw configError(`A provider needs a non-empty "id".`);
  const label = `Provider ${JSON.stringify(provider.id)}`;
  if (typeof provider.start !== "function" || typeof provider.complete !== "function") {
    throw configError(`${label} is custom and needs "start" and "complete".`);
  }
  if (
    provider.responseMode !== undefined &&
    !["query", "form_post"].includes(provider.responseMode)
  ) {
    throw configError(`${label} has an unknown "responseMode".`);
  }
}

function defaultTokenAuth(client: ProviderConfig["client"]): TokenAuthMethod {
  if (client.privateKey) return "private_key_jwt";
  return client.secret ? "basic" : "none";
}
