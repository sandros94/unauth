import { hash, secureCompare } from "unsecure";

/**
 * PKCE verification helper shared with authorize.ts semantics
 */
export async function validatePKCE(
  codeVerifier: string,
  codeChallenge: string,
  codeChallengeMethod: "plain" | "S256" = "plain",
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

export function isScopeSubset(requested: string, available: string[]): boolean {
  const set = new Set(available);
  return requested
    .split(/\s+/g)
    .filter(Boolean)
    .every((s) => set.has(s));
}

/**
 * Normalize audience (aud) claim from string or array; throws if missing/empty.
 */
export function normalizeAudience(
  aud: string | string[] | undefined,
): string | string[] {
  if (aud == null) {
    throw new Error("[OAuth] Missing audience (aud)");
  }
  if (Array.isArray(aud)) {
    const vals = aud.map((s) => String(s).trim()).filter(Boolean);
    if (vals.length === 0) throw new Error("[OAuth] Missing audience (aud)");
    return vals;
  }
  const v = String(aud).trim();
  if (!v) throw new Error("[OAuth] Missing audience (aud)");
  return v;
}

export function buildAuthorizeErrorParams(
  error: string,
  description?: string,
  state?: string,
): [string, string][] {
  const params: [string, string][] = [["error", error]];
  if (description) params.push(["error_description", description]);
  if (state) params.push(["state", state]);
  return params;
}
