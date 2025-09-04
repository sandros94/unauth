import { type JWSAlgorithm, sign } from "unjwt/jws";
import { hash, secureCompare } from "unsecure";

import type { JWTClaims } from "unjwt";
import type { MaybePromise } from "../types/index";
import type {
  OIDCBuildIdTokenArgs,
  OIDCIdTokenClaims,
  OIDCIdTokenOptions,
} from "./types";
import {
  type ResolvedOIDCIdTokenOptions,
  withIdTokenDefaults,
} from "./defaults";

/**
 * Compute token hash (at_hash / c_hash) per OIDC Core 3.3.2.11: base64url( left-most half of hash(access_token) )
 * Hash algorithm is based on the JWS alg, e.g., RS256 -> SHA-256
 */
export async function computeTokenHash(
  value: string,
  jwsAlg: string,
  eddsaHashAlgorithm: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-512",
): Promise<string> {
  if (!jwsAlg) {
    throw new Error("[OIDC] jwsAlg is required to compute token hash");
  }

  const alg = jwsAlg.toUpperCase();
  // Map JOSE alg to underlying hash algorithm length
  const map: Record<string, "SHA-256" | "SHA-384" | "SHA-512"> = {
    HS256: "SHA-256",
    RS256: "SHA-256",
    ES256: "SHA-256",
    PS256: "SHA-256",
    HS384: "SHA-384",
    RS384: "SHA-384",
    ES384: "SHA-384",
    PS384: "SHA-384",
    HS512: "SHA-512",
    RS512: "SHA-512",
    ES512: "SHA-512",
    PS512: "SHA-512",
    Ed25519: eddsaHashAlgorithm,
    EdDSA: eddsaHashAlgorithm,
  } satisfies Record<JWSAlgorithm, "SHA-256" | "SHA-384" | "SHA-512">;
  const algorithm = map[alg];
  if (!algorithm) {
    throw new Error(`[OIDC] Unsupported JWS alg for *_hash: ${jwsAlg}`);
  }
  // Compute full hash as base64url, then decode to bytes for halving
  const fullB64Url = await hash(value, { algorithm, returnAs: "b64url" });
  // convert base64url -> base64 for Buffer decoding
  const fullB64 = fullB64Url.replace(/-/g, "+").replace(/_/g, "/");
  const fullBuf = Buffer.from(fullB64, "base64");
  const halfBuf = fullBuf.subarray(0, Math.floor(fullBuf.length / 2));
  // encode back to base64url
  return halfBuf
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Build and sign an ID Token.
 */
export async function buildIdToken(
  args: OIDCBuildIdTokenArgs,
  options: OIDCIdTokenOptions,
  cb?: (
    args: OIDCBuildIdTokenArgs,
    opts: ResolvedOIDCIdTokenOptions,
  ) => MaybePromise<Partial<JWTClaims> & { scope?: string }>,
): Promise<string> {
  const {
    subject,
    audience,
    nonce,
    auth_time,
    acr,
    amr,
    azp,
    access_token,
    code,
    additionalClaims,
  } = args;
  const { issuer, jwsKey, signOptions } = withIdTokenDefaults(options);
  const eddsaHashAlgorithm = options.eddsaHashAlgorithm || "SHA-512";
  const alg = jwsKey.alg || signOptions.alg;

  const extraClaims = cb ? await cb(args, { issuer, jwsKey, signOptions }) : {};

  const claims: Omit<OIDCIdTokenClaims, "exp"> = {
    ...additionalClaims,
    ...extraClaims,
    iss: issuer,
    sub: subject,
    aud: audience,
    ...(nonce ? { nonce } : {}),
    ...(auth_time
      ? {
          auth_time:
            typeof auth_time === "number"
              ? auth_time
              : Math.floor(auth_time.getTime() / 1000),
        }
      : {}),
    ...(acr ? { acr } : {}),
    ...(amr ? { amr } : {}),
    ...(azp ? { azp } : {}),
  };

  const [at_hash, c_hash] = await Promise.all([
    alg && access_token
      ? computeTokenHash(access_token, alg, eddsaHashAlgorithm)
      : undefined,
    alg && code ? computeTokenHash(code, alg, eddsaHashAlgorithm) : undefined,
  ]);
  if (!("at_hash" in claims) && at_hash) {
    claims.at_hash = at_hash;
  }
  if (!("c_hash" in claims) && c_hash) {
    claims.c_hash = c_hash;
  }

  return sign(claims, jwsKey, {
    protectedHeader: { typ: "at+jwt", ...signOptions.protectedHeader },
    ...signOptions,
  });
}

/**
 * Verify ID Token hash claims (at_hash and c_hash) against provided values.
 * This is intended for clients or token validators, not for the authorize request.
 */
export async function verifyIdTokenHashes(
  claims: OIDCIdTokenClaims,
  jwsAlg: string,
  args: { access_token?: string; code?: string },
): Promise<void> {
  const [atHash, cHash] = await Promise.all([
    claims.at_hash && args.access_token
      ? computeTokenHash(args.access_token, jwsAlg)
      : undefined,
    claims.c_hash && args.code
      ? computeTokenHash(args.code, jwsAlg)
      : undefined,
  ]);

  if (atHash && !secureCompare(claims.at_hash!, atHash)) {
    throw new Error("[OIDC] at_hash validation failed");
  }
  if (cHash && !secureCompare(claims.c_hash!, cHash)) {
    throw new Error("[OIDC] c_hash validation failed");
  }
}
