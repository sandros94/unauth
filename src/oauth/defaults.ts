import type {
  JWEEncryptOptions,
  JWSSignOptions,
} from "unjwt";

import type { OAuthTokenOptions } from "./token";
import type { OAuthAuthorizeOptions } from "./authorize";

import type { Require } from "../types";

export const DEFAULTS = Object.freeze({
  tokenType: "Bearer" as const,
  authorizationCodeExpiresIn: 600, // 10 minutes
  accessTokenExpiresIn: 3600, // 1 hour
  refreshTokenExpiresIn: 60 * 60 * 24 * 30, // 30 days
  codeChallengeMethod: "plain" as const,
  randomJti: () => crypto.randomUUID(),
});

export type ResolvedAuthorizeOptions = Require<OAuthAuthorizeOptions, "randomJti" | "encryptOptions.expiresIn" | "signOptions.expiresIn">;

export type ResolvedTokenOptions = Require<OAuthTokenOptions, "randomJti" | "encryptOptions.expiresIn" | "signOptions.expiresIn">;

/**
 * Apply defaults for the Authorization endpoint helpers.
 */
export function withAuthorizeDefaults<
  T extends OAuthAuthorizeOptions,
>(opts: T): ResolvedAuthorizeOptions {
  const encryptOptions: JWEEncryptOptions & { expiresIn: number } =
    opts.encryptOptions
      ? ({
          ...opts.encryptOptions,
          expiresIn:
            opts.encryptOptions.expiresIn ??
            DEFAULTS.authorizationCodeExpiresIn,
        } as JWEEncryptOptions & { expiresIn: number })
      : ({
          expiresIn: DEFAULTS.authorizationCodeExpiresIn,
        } as JWEEncryptOptions & { expiresIn: number });

  return {
    issuer: opts.issuer,
    jweSecret: opts.jweSecret,
    encryptOptions,
    randomJti: opts.randomJti || DEFAULTS.randomJti,
    defaultScope: opts.defaultScope,
    availableScopes: opts.availableScopes,
  };
}

/**
 * Apply defaults for the Token endpoint helpers.
 */
export function withTokenDefaults<
  T extends OAuthTokenOptions,
>(opts: T): ResolvedTokenOptions {
  const encryptOptions: JWEEncryptOptions & { expiresIn: number } =
    opts.encryptOptions
      ? ({
          ...opts.encryptOptions,
          expiresIn:
            opts.encryptOptions.expiresIn ?? DEFAULTS.refreshTokenExpiresIn,
        } as JWEEncryptOptions & { expiresIn: number })
      : ({ expiresIn: DEFAULTS.refreshTokenExpiresIn } as JWEEncryptOptions & {
          expiresIn: number;
        });

  const signOptions: JWSSignOptions & { expiresIn: number } = opts.signOptions
    ? ({
        ...opts.signOptions,
        expiresIn: opts.signOptions.expiresIn ?? DEFAULTS.accessTokenExpiresIn,
      } as JWSSignOptions & { expiresIn: number })
    : ({ expiresIn: DEFAULTS.accessTokenExpiresIn } as JWSSignOptions & {
        expiresIn: number;
      });

  return {
    issuer: opts.issuer,
    jweSecret: opts.jweSecret,
    jwsPrivateKey: opts.jwsPrivateKey,
    decryptOptions: opts.decryptOptions,
    encryptOptions,
    signOptions,
    verifyOptions: opts.verifyOptions,
    randomJti: opts.randomJti || DEFAULTS.randomJti,
    defaultScope: opts.defaultScope,
    availableScopes: opts.availableScopes,
  };
}
