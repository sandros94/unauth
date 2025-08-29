import type { JWSSignOptions } from "unjwt";
import type { OIDCIdTokenOptions } from "./types";

export const OIDC_DEFAULTS = Object.freeze({
  idTokenExpiresIn: 3600, // 1 hour
});

export type ResolvedOIDCIdTokenOptions = Omit<
  OIDCIdTokenOptions,
  "signOptions"
> & {
  signOptions: JWSSignOptions & { expiresIn: number };
};

export function withIdTokenDefaults(
  opts:
    | OIDCIdTokenOptions
    | (Omit<OIDCIdTokenOptions, "signOptions"> & {
        signOptions?: Partial<JWSSignOptions> & {
          alg: string;
          expiresIn?: number;
        };
      }),
): ResolvedOIDCIdTokenOptions {
  const { issuer, jwsKey } = opts;
  const signOptions = (opts as OIDCIdTokenOptions).signOptions || {
    alg: (opts as any).signOptions?.alg,
  };
  if (!signOptions || !signOptions.alg) {
    throw new Error(
      "[OIDC] signOptions.alg is required to compute *_hash claims",
    );
  }
  const resolvedSign: JWSSignOptions & { expiresIn: number } = {
    ...signOptions,
    expiresIn: signOptions.expiresIn ?? OIDC_DEFAULTS.idTokenExpiresIn,
  };

  return { issuer, jwsKey, signOptions: resolvedSign };
}
