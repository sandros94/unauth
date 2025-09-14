import type { JWK, JWKSet, JWSVerifyResult } from "unjwt";
import { verify } from "unjwt/jws";

import type { ResolvedOIDCOptions } from "./defaults";
import type { IdTokenClaims } from "../types";

// Utility to introspect ID tokens while validating their claims
export async function introspectIdToken(
  token: string,
  key: JWK | JWKSet,
  options: ResolvedOIDCOptions,
): Promise<JWSVerifyResult<IdTokenClaims>> {
  const { issuer, idToken } = options;

  return verify<IdTokenClaims>(token, key, {
    issuer,
    typ: "at+jwt",
    maxTokenAge: idToken.signOptions.expiresIn,
    ...idToken?.verifyOptions,
  });
}
