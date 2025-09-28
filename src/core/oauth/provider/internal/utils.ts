import { hash, secureCompare } from "unsecure";

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
