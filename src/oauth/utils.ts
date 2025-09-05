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
  const raw = (requested || fallback || "").trim();
  if (!raw) {
    throw new Error("[OAuth] Missing scope");
  }

  const tokens = raw.split(/\s+/g).filter(Boolean);
  const deduped = [...new Set(tokens)];
  if (available && available.length > 0) {
    for (const s of deduped) {
      if (!available.includes(s)) {
        throw new Error(`[OAuth] Invalid scope: ${s}`);
      }
    }
  }

  return deduped.join(" ");
}

export function isScopeSubset(requested: string, original: string): boolean {
  const set = new Set(original.split(/\s+/g).filter(Boolean));
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

/**
 * Redact a sensitive token for logging: keep prefix and last 4 characters.
 */
export function redactToken(token: string, prefixLen = 6): string {
  if (!token) return "<empty>";
  const start = token.slice(0, Math.max(0, prefixLen));
  const end = token.slice(-4);
  return `${start}…${end}`;
}
