import type { JWKSet } from "unjwt";
import { type Fetch, assertSecureUrl, fetchOf, isRecord, nowOf, providerError } from "./_http.ts";
import { getObject } from "./_http-json.ts";
import { type CacheDriver, JWKS_REFRESH_COOLDOWN, loadCache } from "./_cache.ts";

const cache = /* @__PURE__ */ loadCache<JWKSet>({ name: "jwks", check: parseJwks });

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
  /** Development only: hosts whose JWKS URL may use plain `http:` (see `Provider.insecureHosts`). */
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
  return cache.get(url, () => loadJwks(url, fetchOf(options)), {
    now: nowOf(options),
    force: options?.force,
    cooldown: JWKS_REFRESH_COOLDOWN,
    scope: options?.fetch,
    driver: options?.cache,
  });
}

async function loadJwks(url: string, fetch: Fetch): Promise<JWKSet> {
  return parseJwks(await getObject(url, { fetch, label: "JWK Set" }), url);
}

/** The key set `body` holds, dropping members that are not objects. */
function parseJwks(body: unknown, url: string): JWKSet {
  const keys = isRecord(body) ? body.keys : undefined;
  if (!Array.isArray(keys)) throw providerError(`The JWK Set at ${url} has no "keys" array.`);
  return { keys: keys.filter((key) => typeof key === "object" && key !== null) };
}
