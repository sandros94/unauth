import { type JWEDecryptResult, decrypt } from "unjwt/jwe";
import { type JWSVerifyResult, verify } from "unjwt/jws";

import type {
  AuthorizationCodeClaims,
  AccessTokenClaims,
  RefreshTokenClaims,
} from "../../types";
import type {
  AuthorizationCodeOptions,
  AccessTokenOptions,
  RefreshTokenOptions,
} from "./defaults";
import {
  authorizationCodeDefaults,
  accessTokenDefaults,
  refreshTokenDefaults,
} from "./defaults";

// Utility to introspect refresh tokens while validating their claims
export async function introspectAuthorizationCode(args: {
  token: string;
  iss: string;
  options: AuthorizationCodeOptions;
}): Promise<JWEDecryptResult<AuthorizationCodeClaims>> {
  const { token, iss, options } = args;
  const opts = authorizationCodeDefaults(options);

  return decrypt<AuthorizationCodeClaims>(token, opts.privateKey, {
    issuer: iss,
    maxTokenAge: opts.encryptOptions.expiresIn,
    ...opts.decryptOptions,
  });
}

// Utility to introspect access tokens while validating their claims
export async function introspectAccessToken(args: {
  token: string;
  iss: string;
  options: AccessTokenOptions;
}): Promise<JWSVerifyResult<AccessTokenClaims>> {
  const { token, iss, options } = args;
  const opts = accessTokenDefaults(options);

  return verify<AccessTokenClaims>(token, opts.privateKey, {
    issuer: iss,
    typ: "at+jwt",
    maxTokenAge: opts.signOptions.expiresIn,
    ...opts.verifyOptions,
  });
}

// Utility to introspect refresh tokens while validating their claims
export async function introspectRefreshToken(args: {
  token: string;
  iss: string;
  options: RefreshTokenOptions;
}): Promise<JWEDecryptResult<RefreshTokenClaims>> {
  const { token, iss, options } = args;
  const opts = refreshTokenDefaults(options);

  return decrypt<RefreshTokenClaims>(token, opts.privateKey, {
    issuer: iss,
    maxTokenAge: opts.encryptOptions.expiresIn,
    ...opts.decryptOptions,
  });
}
