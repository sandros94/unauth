import { hash, secureCompare } from "unsecure";
import { decrypt } from "unjwt/jwe";
import { verify } from "unjwt/jws";

import type {
  OAuthRefreshTokenClaims,
  OAuthAuthorizationCodeClaims,
  OAuthAccessTokenClaims,
} from "./types";
import type { OAuthTokenOptions } from "./token";

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
 * Utility to introspect tokens.
 * For authorization code and refresh tokens (JWE), decrypts it; for access tokens (JWS), verifies it.
 */
export async function introspectToken<T extends OAuthAccessTokenClaims>(
  token: string,
  opts: Pick<OAuthTokenOptions, "issuer" | "jwsPrivateKey" | "verifyOptions">,
): Promise<{ active: boolean; claims?: T }>;
export async function introspectToken<
  T extends OAuthRefreshTokenClaims | OAuthAuthorizationCodeClaims,
>(
  token: string,
  opts: Pick<OAuthTokenOptions, "issuer" | "jweSecret" | "decryptOptions">,
): Promise<{ active: boolean; claims?: T }>;
export async function introspectToken<
  T extends
    | OAuthRefreshTokenClaims
    | OAuthAuthorizationCodeClaims
    | OAuthAccessTokenClaims,
>(
  token: string,
  opts:
    | Pick<OAuthTokenOptions, "issuer" | "jweSecret" | "decryptOptions">
    | Pick<OAuthTokenOptions, "issuer" | "jwsPrivateKey" | "verifyOptions">,
): Promise<{ active: boolean; claims?: T }> {
  try {
    if ("jwsPrivateKey" in opts) {
      const { payload } = await verify<T>(token, opts.jwsPrivateKey, {
        issuer: opts.issuer,
        typ: "at+jwt",
        ...opts.verifyOptions,
      });
      return { active: true, claims: payload };
    } else if ("jweSecret" in opts) {
      const { payload } = await decrypt<T>(token, opts.jweSecret, {
        issuer: opts.issuer,
        typ: "at+jwt",
        ...opts.decryptOptions,
      });
      return { active: true, claims: payload };
    } else {
      throw new Error("[OAuth] Unsupported token type");
    }
  } catch {
    return { active: false, claims: undefined };
  }
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
