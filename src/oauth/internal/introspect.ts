import { type JWEDecryptResult, decrypt } from "unjwt/jwe";
import { type JWSVerifyResult, verify } from "unjwt/jws";
import type { JWK, JWKSet } from "unjwt";

import type {
  AuthorizationCodeClaims,
  AccessTokenClaims,
  RefreshTokenClaims,
} from "../types";
import type { ResolvedOAuthOptions } from "./defaults";

// Utility to introspect refresh tokens while validating their claims
export async function introspectAuthorizationCode(
  token: string,
  privateKey: string | JWK,
  options: ResolvedOAuthOptions,
): Promise<JWEDecryptResult<AuthorizationCodeClaims>> {
  const { issuer, authorizationCode } = options;

  return decrypt<AuthorizationCodeClaims>(token, privateKey, {
    issuer,
    maxTokenAge: authorizationCode.encryptOptions.expiresIn,
    ...authorizationCode.decryptOptions,
  });
}

// Utility to introspect access tokens while validating their claims
export async function introspectAccessToken(
  token: string,
  key: JWK | JWKSet,
  options: ResolvedOAuthOptions,
): Promise<JWSVerifyResult<AccessTokenClaims>> {
  const { issuer, accessToken } = options;

  return verify<AccessTokenClaims>(token, key, {
    issuer,
    typ: "at+jwt",
    maxTokenAge: accessToken.signOptions.expiresIn,
    ...accessToken?.verifyOptions,
  });
}

// Utility to introspect refresh tokens while validating their claims
export async function introspectRefreshToken(
  token: string,
  privateKey: string | JWK,
  options: ResolvedOAuthOptions,
): Promise<JWEDecryptResult<RefreshTokenClaims>> {
  const { issuer, refreshToken } = options;

  return decrypt<RefreshTokenClaims>(token, privateKey, {
    issuer,
    maxTokenAge: refreshToken.encryptOptions.expiresIn,
    ...refreshToken?.decryptOptions,
  });
}
