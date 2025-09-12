import { type JWEDecryptResult, decrypt } from "unjwt/jwe";
import { type JWSVerifyResult, verify } from "unjwt/jws";
import type { JWK, JWKSet } from "unjwt";

import type {
  AuthorizationCodeClaims,
  AccessTokenClaims,
  RefreshTokenClaims,
} from "../types"
import type {
  ResolvedAuthorizationCodeOptions,
  ResolvedAccessTokenOptions,
  ResolvedRefreshTokenOptions,
} from "./defaults"

// Utility to introspect refresh tokens while validating their claims
export async function introspectAuthorizationCode(
  token: string,
  privateKey: string | JWK,
  options: ResolvedAuthorizationCodeOptions & { issuer: string; },
): Promise<JWEDecryptResult<AuthorizationCodeClaims>> {
  const { issuer, ...opts } = options;

  return decrypt<AuthorizationCodeClaims>(
    token,
    privateKey,
    {
      issuer,
      maxTokenAge: opts.encryptOptions.expiresIn,
      ...opts.decryptOptions,
    },
  );
}

// Utility to introspect access tokens while validating their claims
export async function introspectAccessToken(
  token: string,
  key: JWK | JWKSet,
  options: ResolvedAccessTokenOptions & { issuer: string; },
): Promise<JWSVerifyResult<AccessTokenClaims>> {
  const { issuer, ...opts } = options;

  return verify<AccessTokenClaims>(
    token,
    key,
    {
      issuer,
      typ: "at+jwt",
      maxTokenAge: opts.signOptions.expiresIn,
      ...opts?.verifyOptions,
    },
  );
}

// Utility to introspect refresh tokens while validating their claims
export async function introspectRefreshToken(
  token: string,
  privateKey: string | JWK,
  options: ResolvedRefreshTokenOptions & { issuer: string; },
): Promise<JWEDecryptResult<RefreshTokenClaims>> {
  const { issuer, ...opts } = options;

  return decrypt<RefreshTokenClaims>(
    token,
    privateKey,
    {
      issuer,
      maxTokenAge: opts.encryptOptions.expiresIn,
      ...opts?.decryptOptions,
    },
  );
}
