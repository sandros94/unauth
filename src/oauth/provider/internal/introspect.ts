import type { JWK, JWKSet } from "unjwt/jwk";
import { decrypt } from "unjwt/jwe";
import { verify } from "unjwt/jws";
import { isPublicJWK, isSymmetricJWK } from "unjwt/utils";

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
  const key = preferPublicKey(opts);

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

function preferPublicKey(options: {
  publicKey?: JWK | JWK[];
  privateKey: JWK;
}): JWK | JWKSet {
  if (options.publicKey) {
    const key = Array.isArray(options.publicKey)
      ? options.publicKey
      : [options.publicKey];

    return {
      keys: key.filter((element) => isPublicJWK(element)),
    };
  }

  if (!isSymmetricJWK(options.privateKey)) {
    console.warn(
      `Using private key for Access Token verification; ensure "key_ops" includes "verify" and that this is intentional.`,
    );
  }
  return options.privateKey;
}
