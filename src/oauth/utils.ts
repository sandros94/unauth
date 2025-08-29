import { hash, secureCompare } from "unsecure";
import { decrypt } from "unjwt/jwe";
import { verify } from "unjwt/jws";

import type { OAuthRefreshTokenClaims, OAuthAuthorizationCodeClaims, OAuthAccessTokenClaims } from "./types";
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

/**
 * Utility to introspect tokens.
 * For authorization code and refresh tokens (JWE), decrypts it; for access tokens (JWS), verifies it.
 */
export async function introspectToken<T extends OAuthAccessTokenClaims>(
  token: string,
  opts: Pick<OAuthTokenOptions, "issuer" | "jwsKey" | "verifyOptions">,
): Promise<{ active: boolean; claims?: T }>
export async function introspectToken<T extends OAuthRefreshTokenClaims | OAuthAuthorizationCodeClaims>(
  token: string,
  opts: Pick<OAuthTokenOptions, "issuer" | "jweSecret" | "decryptOptions">,
): Promise<{ active: boolean; claims?: T }>
export async function introspectToken<T extends OAuthRefreshTokenClaims | OAuthAuthorizationCodeClaims | OAuthAccessTokenClaims>(
  token: string,
  opts: Pick<OAuthTokenOptions, "issuer" | "jweSecret" | "decryptOptions"> | Pick<OAuthTokenOptions, "issuer" | "jwsKey" | "verifyOptions">,
): Promise<{ active: boolean; claims?: T }> {
  try {
    if ('jwsKey' in opts) {
      const { payload } = await verify<T>(token, opts.jwsKey, {
        issuer: opts.issuer,
        ...opts.verifyOptions,
      });
      return { active: true, claims: payload };
    }
    else if ('jweSecret' in opts) {
      const { payload } = await decrypt<T>(token, opts.jweSecret, {
        issuer: opts.issuer,
        ...opts.decryptOptions,
      });
      return { active: true, claims: payload };
    }
    else {
      throw new Error("[OAuth] Unsupported token type");
    }
  } catch {
    return { active: false, claims: undefined };
  }
}
