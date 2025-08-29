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

export function normalizeScope(
  requested: string | undefined,
  fallback: string | undefined,
  available?: string[],
): string {
  const scope = (requested || fallback || "").trim();
  if (!scope) {
    throw new Error("[OAuth] Missing scope");
  }
  if (!available || available.length === 0) return scope;
  const requestedSet = new Set(scope.split(/\s+/g).filter(Boolean));
  for (const s of requestedSet) {
    if (!available.includes(s)) {
      throw new Error(`[OAuth] Invalid scope: ${s}`);
    }
  }
  return [...requestedSet].join(" ");
}

export function isScopeSubset(requested: string, original: string): boolean {
  const set = new Set(original.split(/\s+/g).filter(Boolean));
  return requested
    .split(/\s+/g)
    .filter(Boolean)
    .every((s) => set.has(s));
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
