import { verify } from "unjwt/jws";

import type { IdTokenClaims } from "../../types";
import { type IdTokenOptions, idTokenDefaults } from "./defaults";
import { preferPublicKey } from "../../../oauth/provider/internal/utils";

export * from "../../../oauth/provider/internal/introspect";

// Utility to introspect id tokens while validating their claims
export async function introspectIdToken<T extends IdTokenClaims>(args: {
  token: string;
  iss: string;
  options: IdTokenOptions;
}): Promise<T> {
  const { token, iss, options } = args;
  const opts = idTokenDefaults(options);
  const key = preferPublicKey(opts, { tokenType: "ID Token" });

  const { payload } = await verify<T>(token, key, {
    issuer: iss,
    typ: "id+jwt",
    maxTokenAge: opts.signOptions.expiresIn,
    ...opts.verifyOptions,
  });

  return payload;
}
