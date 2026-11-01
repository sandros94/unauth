import { type Fetch, configError } from "./http/shared.ts";
import type { CacheDriver } from "./cache/load.ts";
import { verifyIdToken } from "../id-token.ts";
import type { IdTokenClaims, OAuthProvider } from "../types.ts";

/**
 * Verifies `idToken` as one `provider` issued to this client: its `issuer`, its `jwks`, its
 * `client.id`, its `insecureHosts`. A provider naming no issuer or key set throws
 * `ERR_UNAUTH_CONFIG_INVALID`; see `verifyIdToken` for the rest.
 */
export function verifyProviderIdToken(
  provider: OAuthProvider<unknown>,
  options: {
    idToken: string;
    accessToken: string;
    nonce?: string;
    subject?: string;
    fetch: Fetch;
    now: () => number;
    cache?: CacheDriver;
  },
): Promise<IdTokenClaims> {
  const { issuer, jwks } = provider;
  if (!issuer || !jwks) {
    throw configError(
      `OAuthProvider ${JSON.stringify(provider.id)} needs "issuer" and "jwks" to verify id_tokens; pass it through resolveProvider() first.`,
    );
  }
  return verifyIdToken(options.idToken, {
    issuer,
    clientId: provider.client.id,
    nonce: options.nonce,
    subject: options.subject,
    jwks,
    accessToken: options.accessToken,
    fetch: options.fetch,
    now: options.now,
    cache: options.cache,
    insecureHosts: provider.insecureHosts,
  });
}
