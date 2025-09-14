import { sign } from "unjwt/jws";
import type { JWK, JWSAlgorithm } from "unjwt";
import { hash, secureCompare } from "unsecure";

import type { AccessTokenClaims } from "../../oauth";
import type { IdTokenClaims } from "../types";
import type { ResolvedOIDCOptions } from "./defaults";

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
  const algorithm = map[jwsAlg];
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
 * Verify ID Token hash claims (at_hash and c_hash) against provided values.
 * This is intended for clients or token validators, not for the authorize request.
 */
export async function verifyIdTokenHashes(
  claims: IdTokenClaims,
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

async function buildIdTokenClaims(
  args: {
    access?: string;
    code?: string;
    nonce?: string;
  },
  accessTokenClaims: AccessTokenClaims,
  opts: ResolvedOIDCOptions,
  idTokenKey?: JWK,
): Promise<IdTokenClaims> {
  const { issuer } = opts;
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + (opts.idToken.signOptions?.expiresIn ?? 600);
  const aud = accessTokenClaims.client_id;
  const base: IdTokenClaims = {
    iss: issuer,
    sub: accessTokenClaims.sub,
    aud,
    iat,
    exp,
  };

  // Compute at_hash or c_hash if respective input provided and alg known
  const alg = idTokenKey?.alg || opts.idToken.privateKey.alg;
  if (alg) {
    const [atHash, cHash] = await Promise.all([
      args.access ? computeTokenHash(args.access, alg) : undefined,
      args.code ? computeTokenHash(args.code, alg) : undefined,
    ]);
    base.at_hash = atHash;
    base.c_hash = cHash;
  }
  if (args.nonce) base.nonce = args.nonce;

  const hookExtras = (await opts.hooks?.onIdTokenClaims?.({
    reason: args.code ? "authorization_code" : "refresh_token",
    accessToken: accessTokenClaims,
    refreshToken: undefined,
    nonce: args.nonce,
  })) as Partial<IdTokenClaims> | undefined;

  return {
    ...base,
    ...(hookExtras && { ...hookExtras }),
  };
}

export async function signIdToken(
  args: {
    access?: string;
    code?: string;
    nonce?: string;
  },
  accessTokenClaims: AccessTokenClaims,
  opts: ResolvedOIDCOptions,
  idTokenKey?: JWK,
) {
  const claims = await buildIdTokenClaims(
    args,
    accessTokenClaims,
    opts,
    idTokenKey,
  );

  return sign(
    claims,
    idTokenKey || opts.idToken.privateKey,
    opts.idToken.signOptions,
  );
}
