import { type JWSVerifyResult, verify } from "unjwt/jws";

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

  return verify<IdTokenClaims>(token, opts.privateKey, {
    issuer: iss,
    typ: "id+jwt",
    maxTokenAge: opts.signOptions.expiresIn,
    ...opts.verifyOptions,
  });
}
