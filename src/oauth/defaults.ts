import type {
  JWK,
  JWEEncryptOptions,
  JWEDecryptOptions,
  JWSSignOptions,
  JWSVerifyOptions,
} from "unjwt";

export const DEFAULTS = Object.freeze({
  tokenType: "Bearer" as const,
  authorizationCodeExpiresIn: 600, // 10 minutes
  accessTokenExpiresIn: 3600, // 1 hour
  refreshTokenExpiresIn: 60 * 60 * 24 * 30, // 30 days
  codeChallengeMethod: "plain" as const,
  randomJti: () => crypto.randomUUID(),
});

export type ResolvedAuthorizeOptions = {
  issuer: string;
  jweSecret: string | JWK;
  encryptOptions: JWEEncryptOptions & { expiresIn: number };
  randomJti: () => string;
  defaultScope?: string;
  availableScopes?: string[];
};

export type ResolvedTokenOptions = {
  issuer: string;
  jweSecret: string | JWK;
  jwsKey: JWK;
  decryptOptions?: JWEDecryptOptions;
  encryptOptions: JWEEncryptOptions & { expiresIn: number };
  signOptions: JWSSignOptions & { expiresIn: number };
  verifyOptions?: JWSVerifyOptions;
  randomJti: () => string;
  defaultScope?: string;
  availableScopes?: string[];
};

/**
 * Apply defaults for the Authorization endpoint helpers.
 */
export function withAuthorizeDefaults<
  T extends {
    issuer: string;
    jweSecret: string | JWK;
    encryptOptions?: JWEEncryptOptions & { expiresIn?: number };
    randomJti?: () => string;
    defaultScope?: string;
    availableScopes?: string[];
  },
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
  T extends {
    issuer: string;
    jweSecret: string | JWK;
    jwsKey: JWK;
    decryptOptions?: any;
    encryptOptions?: JWEEncryptOptions & { expiresIn?: number };
    signOptions?: JWSSignOptions & { expiresIn?: number };
    verifyOptions?: JWSVerifyOptions;
    randomJti?: () => string;
    defaultScope?: string;
    availableScopes?: string[];
  },
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
    jwsKey: opts.jwsKey,
    decryptOptions: opts.decryptOptions,
    encryptOptions,
    signOptions,
    verifyOptions: opts.verifyOptions,
    randomJti: opts.randomJti || DEFAULTS.randomJti,
    defaultScope: opts.defaultScope,
    availableScopes: opts.availableScopes,
  };
}
