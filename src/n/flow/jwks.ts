import type { JWKSet } from "unjwt/jwk";
import {
  type Fetch,
  assertSecureUrl,
  fetchOf,
  isRecord,
  nowOf,
  providerError,
} from "./_internal/http/shared.ts";
import { type CacheDriver, JWKS_REFRESH_COOLDOWN } from "./_internal/cache/load.ts";
import { defineMetadataLoader } from "./_internal/cache/metadata.ts";

const load = /* @__PURE__ */ defineMetadataLoader<JWKSet>({
  name: "jwks",
  label: "JWK Set",
  url: (url) => url,
  parse: parseJwks,
  cooldown: JWKS_REFRESH_COOLDOWN,
});

/** Options of {@link fetchJwks}. */
export interface FetchJwksOptions {
  fetch?: Fetch;
  now?: () => number;
  /**
   * Fetch again, as for a `kid` the cached set lacks; honored only once the cached set is 30
   * seconds old, so unknown `kid`s cannot drive a refetch per request.
   */
  force?: boolean;
  /** Keep the set here instead of in memory. */
  cache?: CacheDriver;
  /** Development only: hosts whose JWKS URL may use plain `http:` (see `OAuthProvider.insecureHosts`). */
  insecureHosts?: string[];
}

/**
 * The JWK Set at `url`, kept for ten minutes per URL: in memory per injected `fetch`, or in
 * `options.cache`. The URL must be `https:` (or `http:` on localhost or a host in
 * `insecureHosts`), else `ERR_UNAUTH_CONFIG_INVALID`.
 * Concurrent callers share one request; a failed fetch throws `ERR_AUTHN_PROVIDER_ERROR`, rethrown
 * without a fetch for five seconds. id_token verification refetches only for a `kid` the cached
 * set lacks: a key replaced under the same `kid` is picked up when the ten minutes run out.
 */
export async function fetchJwks(url: string, options?: FetchJwksOptions): Promise<JWKSet> {
  assertSecureUrl(url, { label: "The JWKS URL", insecureHosts: options?.insecureHosts });
  return load(url, {
    fetch: fetchOf(options),
    now: nowOf(options),
    cache: options?.cache,
    force: options?.force,
  });
}

/** The key set `body` holds, dropping members that are not objects. */
function parseJwks(body: unknown, url: string): JWKSet {
  const keys = isRecord(body) ? body.keys : undefined;
  if (!Array.isArray(keys))
    throw providerError(`The JWK Set at ${url} has no "keys" array.`, { reason: "malformed" });
  return { keys: keys.filter((key) => typeof key === "object" && key !== null) };
}
