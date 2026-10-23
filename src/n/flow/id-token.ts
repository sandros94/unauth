import { type JWKSet, type JWSAlgorithm, type JWSVerifyResult, verify } from "unjwt";
import { type DigestAlgorithm, hash } from "unsecure/hash";
import { base64Stringify } from "unsecure/utils";
import { secureCompare } from "unsecure/compare";
import { UnauthError, isUnauthError } from "../../_internal/error.ts";
import { type Fetch, nowOf } from "./_http.ts";
import type { CacheDriver } from "./_cache.ts";
import { fetchJwks } from "./jwks.ts";
import type { IdTokenClaims } from "./types.ts";

/** Signature algorithms an id_token may use: asymmetric only, so a client secret cannot forge one. */
const ASYMMETRIC_ALGORITHMS: JWSAlgorithm[] = [
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "Ed25519",
  "EdDSA",
];

/** Options of {@link verifyIdToken}. */
export interface VerifyIdTokenOptions {
  /** The issuer the token must name in `iss`, exactly. */
  issuer: string;
  /** The `client_id` the token must name in `aud` (and `azp` when present). */
  clientId: string;
  /** The nonce sent with the authorization request; the token must carry it. */
  nonce?: string;
  /**
   * The JWKS URL (cached, refetched for an unknown `kid` once the cached set is 30 seconds old) or
   * a key set in hand.
   */
  jwks: string | JWKSet;
  /** The access token issued alongside; checked against `at_hash` when the token carries one. */
  accessToken?: string;
  /** Seconds of clock skew allowed on `exp` and `iat`. @default 30 */
  clockTolerance?: number;
  fetch?: Fetch;
  now?: () => number;
  /** Keep the fetched JWK Set here instead of in memory. */
  cache?: CacheDriver;
  /** Development only: hosts whose JWKS URL may use plain `http:` (see `OAuthProvider.insecureHosts`). */
  insecureHosts?: string[];
}

/**
 * Verifies an OpenID Connect id_token (OIDC Core §3.1.3.7): an asymmetric signature from the
 * issuer's keys, `iss`, `aud`/`azp`, `exp`, `iat`, `nonce` and, when present, `at_hash`. Failures
 * throw `ERR_AUTHN_ID_TOKEN_INVALID` (401); an unreachable key set throws `ERR_AUTHN_PROVIDER_ERROR`.
 */
export async function verifyIdToken(
  idToken: string,
  options: VerifyIdTokenOptions,
): Promise<IdTokenClaims> {
  const { jwks, issuer, clientId } = options;
  const now = nowOf(options);
  const lookup = async (header: { kid?: string }): Promise<JWKSet> => {
    if (typeof jwks !== "string") return jwks;
    const set = await fetchJwks(jwks, options);
    if (header.kid === undefined || set.keys.some((key) => key.kid === header.kid)) return set;
    return fetchJwks(jwks, { ...options, force: true });
  };

  let verified: JWSVerifyResult<IdTokenClaims>;
  try {
    verified = await verify<IdTokenClaims>(idToken, lookup, {
      algorithms: ASYMMETRIC_ALGORITHMS,
      issuer,
      audience: clientId,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
      currentDate: new Date(now()),
      clockTolerance: options.clockTolerance ?? 30,
    });
  } catch (error) {
    throw unauthCause(error) ?? invalid("The id_token failed verification.", error);
  }

  const claims = verified.payload;
  if (typeof claims.sub !== "string" || claims.sub === "") {
    throw invalid("The id_token names no subject.", { claim: "sub" });
  }
  const tolerance = options.clockTolerance ?? 30;
  if (claims.iat > now() / 1000 + tolerance || claims.iat > claims.exp) {
    throw invalid("The id_token was issued at an impossible time.", { claim: "iat" });
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (claims.azp === undefined ? audiences.length > 1 : claims.azp !== clientId) {
    throw invalid("The id_token was issued to another party.", { claim: "azp" });
  }
  if (options.nonce !== undefined && !secureCompare(options.nonce, stringClaim(claims.nonce))) {
    throw invalid("The id_token does not belong to this sign-in.", { claim: "nonce" });
  }
  if (claims.at_hash !== undefined && options.accessToken !== undefined) {
    const expected = await accessTokenHash(options.accessToken, verified.protectedHeader.alg);
    if (!secureCompare(expected, stringClaim(claims.at_hash))) {
      throw invalid("The id_token does not match its access token.", { claim: "at_hash" });
    }
  }
  return claims;
}

/** OIDC Core §3.1.3.6: base64url of the left half of the access token's hash under the token's alg. */
async function accessTokenHash(accessToken: string, alg: string): Promise<string> {
  const digest = await hash(accessToken, { algorithm: digestFor(alg), returnAs: "bytes" });
  return base64Stringify(digest.slice(0, digest.length / 2), { alphabet: "base64url" });
}

function digestFor(alg: string): DigestAlgorithm {
  if (alg.startsWith("Ed") || alg.endsWith("512")) return "SHA-512";
  return alg.endsWith("384") ? "SHA-384" : "SHA-256";
}

function stringClaim(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

/** The first `UnauthError` in a cause chain: a key-lookup failure arrives wrapped by `verify`. */
function unauthCause(error: unknown): UnauthError | undefined {
  for (let current = error, depth = 0; current !== undefined && depth < 5; depth++) {
    if (isUnauthError(current)) return current;
    current = current instanceof Error ? current.cause : undefined;
  }
  return undefined;
}

function invalid(message: string, cause: unknown): UnauthError<"ERR_AUTHN_ID_TOKEN_INVALID"> {
  return new UnauthError(`[unauth/n] ${message}`, "ERR_AUTHN_ID_TOKEN_INVALID", {
    status: 401,
    cause,
  });
}
