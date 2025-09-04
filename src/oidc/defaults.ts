import type { JWSSignOptions } from "unjwt";
import type { OIDCIdTokenOptions } from "./types";

import type { Require } from "../types";

export const OIDC_DEFAULTS = Object.freeze({
  idTokenExpiresIn: 3600, // 1 hour
});

export type ResolvedOIDCIdTokenOptions = Require<
  OIDCIdTokenOptions,
  "signOptions.expiresIn"
>;

export function withIdTokenDefaults(
  opts: OIDCIdTokenOptions,
): ResolvedOIDCIdTokenOptions {
  const { issuer, jwsKey, signOptions } = opts;

  const resolvedSign: JWSSignOptions & { expiresIn: number } = {
    ...signOptions,
    expiresIn: signOptions?.expiresIn ?? OIDC_DEFAULTS.idTokenExpiresIn,
  };

  return {
    issuer,
    jwsKey,
    signOptions: resolvedSign,
    eddsaHashAlgorithm: opts.eddsaHashAlgorithm,
  };
}
