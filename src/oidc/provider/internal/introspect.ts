import { isPublicJWK, isSymmetricJWK } from "unjwt/utils";
import { type JWSVerifyResult, verify } from "unjwt/jws";
import type { JWK, JWKSet } from "unjwt/jwk";

import type { IdTokenClaims } from "../../types";
import { type IdTokenOptions, idTokenDefaults } from "./defaults";

export * from "../../../oauth/provider/internal/introspect";

// Utility to introspect id tokens while validating their claims
export async function introspectIdToken(args: {
  token: string;
  iss: string;
  options: IdTokenOptions;
}): Promise<JWSVerifyResult<IdTokenClaims>> {
  const { token, iss, options } = args;
  const opts = idTokenDefaults(options);
  const key = preferPublicKey(opts);

  return verify<IdTokenClaims>(token, key, {
    issuer: iss,
    typ: "id+jwt",
    maxTokenAge: opts.signOptions.expiresIn,
    ...opts.verifyOptions,
  });
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
      `Using private key for ID Token verification; ensure "key_ops" includes "verify" and that this is intentional.`,
    );
  }
  return options.privateKey;
}
