import { decrypt } from "unjwt/jwe";
import { verify } from "unjwt/jws";

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
import { preferPublicKey } from "./utils";

// Utility to introspect refresh tokens while validating their claims
export async function introspectAuthorizationCode<
  T extends AuthorizationCodeClaims,
>(args: {
  token: string;
  iss: string;
  options: AuthorizationCodeOptions;
}): Promise<T> {
  const { token, iss, options } = args;
  const opts = authorizationCodeDefaults(options);

  const { payload } = await decrypt<T>(token, opts.privateKey, {
    issuer: iss,
    typ: "ac+jwt",
    maxTokenAge: opts.encryptOptions.expiresIn,
    ...opts.decryptOptions,
  });

  return payload;
}

// Utility to introspect access tokens while validating their claims
export async function introspectAccessToken<T extends AccessTokenClaims>(args: {
  token: string;
  iss: string;
  options: AccessTokenOptions;
}): Promise<T> {
  const { token, iss, options } = args;
  const opts = accessTokenDefaults(options);
  const key = preferPublicKey(opts, { tokenType: "Access Token" });

  const { payload } = await verify<T>(token, key, {
    issuer: iss,
    typ: "at+jwt",
    maxTokenAge: opts.signOptions.expiresIn,
    ...opts.verifyOptions,
  });

  return payload;
}

// Utility to introspect refresh tokens while validating their claims
export async function introspectRefreshToken<
  T extends RefreshTokenClaims,
>(args: {
  token: string;
  iss: string;
  options: RefreshTokenOptions;
}): Promise<T> {
  const { token, iss, options } = args;
  const opts = refreshTokenDefaults(options);

  const { payload } = await decrypt<T>(token, opts.privateKey, {
    issuer: iss,
    typ: "rt+jwt",
    maxTokenAge: opts.encryptOptions.expiresIn,
    ...opts.decryptOptions,
  });

  return payload;
}
