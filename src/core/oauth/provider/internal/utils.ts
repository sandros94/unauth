import { isPublicJWK, isSymmetricJWK, isJWKSet } from "unjwt/utils";
import { hash, secureCompare } from "unsecure";
import type { JWK_Private, JWK_Public, JWKSet } from "unjwt";
import type { MaybeArray } from "../../../../types";

/**
 * PKCE verification helper shared with authorize.ts semantics
 */
export async function validatePKCE(
  codeVerifier: string,
  codeChallenge: string,
  codeChallengeMethod: "plain" | "S256",
): Promise<boolean> {
  if (codeChallengeMethod === "plain") {
    return secureCompare(codeChallenge, codeVerifier);
  }
  const hashedVerifier = await hash(codeVerifier, {
    algorithm: "SHA-256",
    returnAs: "b64url",
  });
  return secureCompare(codeChallenge, hashedVerifier);
}

/**
 * Helper to check if a requested scope is a subset of an allowed scope.
 */
export function isScopeSubset(requested: string, allowed: string): boolean {
  const requestedSet = new Set(requested.split(" "));
  const allowedSet = new Set(allowed.split(" "));
  for (const s of requestedSet) {
    if (!allowedSet.has(s)) {
      return false;
    }
  }
  return true;
}

export function preferPublicKey(
  options: {
    /**
     * The private key to sign the access token.
     */
    privateKey: JWK_Private;
    /**
     * The public key or key set to verify the access token.
     */
    publicKey: MaybeArray<JWK_Public> | JWKSet;
  },
  opts?: {
    tokenType?: "Access Token" | "ID Token" | (string & {});
  },
): JWK_Private | JWKSet {
  if (options.publicKey === undefined) {
    throw new Error(
      `No public key provided for ${opts?.tokenType || "Token"} verification.`,
    );
  } else if (isJWKSet(options.publicKey)) {
    return {
      keys: options.publicKey.keys.filter((key) => isPublicJWK(key)),
    };
  } else if (options.publicKey) {
    const key = Array.isArray(options.publicKey)
      ? options.publicKey
      : [options.publicKey];

    return {
      keys: key.filter((element) => isPublicJWK(element)),
    };
  }

  if (!isSymmetricJWK(options.privateKey)) {
    console.warn(
      `Using private key for ${opts?.tokenType || "Token"} verification; ensure "key_ops" includes "verify" and that this is intentional.`,
    );
  }
  return options.privateKey;
}
