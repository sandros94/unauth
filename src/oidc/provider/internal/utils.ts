import type { JWSAlgorithm } from "unjwt";
import { hash } from "unsecure";

/**
 * Compute token hash (at_hash / c_hash) per OIDC Core 3.3.2.11: base64url( left-most half of hash(access_token) )
 * Hash algorithm is based on the JWS alg, e.g., RS256 -> SHA-256
 */
export async function computeTokenHash(
  value: string,
  jwsAlg: string,
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
    Ed25519: "SHA-512",
    EdDSA: "SHA-512",
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
