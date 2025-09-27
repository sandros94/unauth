import type {
  JWK,
  JWEEncryptOptions,
  JWEDecryptOptions,
  JWSSignOptions,
  JWSVerifyOptions,
} from "unjwt";

import type { MaybeArray, Require } from "../../../types";

export const DEFAULTS_OPTIONS = Object.freeze({
  randomJti: () => crypto.randomUUID(),
  currentDate: new Date(),
  authorizationCode: {
    expiresIn: 60 * 10, // 10 minutes
  },
  refreshToken: {
    expiresIn: 60 * 60 * 24 * 30, // 30 days
  },
  accessToken: {
    expiresIn: 60 * 60, // 1 hour
  },
});

// Authorization Code Options

export interface AuthorizationCodeOptions {
  /**
   * The secret or private key to sign the authorization code token.
   */
  privateKey: string | JWK;
  /**
   * Options for encrypting the authorization code token.
   */
  encryptOptions?: JWEEncryptOptions;
  /**
   * Options for decrypting the authorization code token.
   */
  decryptOptions?: JWEDecryptOptions;
}

export type ResolvedAuthorizationCodeOptions = Require<
  AuthorizationCodeOptions,
  "encryptOptions.expiresIn" | "encryptOptions.currentDate"
>;

/**
 * Apply defaults for the Authorization Code helpers.
 */
export function authorizationCodeDefaults<T extends AuthorizationCodeOptions>(
  opts: T,
): ResolvedAuthorizationCodeOptions {
  return {
    privateKey: opts.privateKey,
    decryptOptions: {
      ...opts.decryptOptions,
      currentDate:
        opts?.decryptOptions?.currentDate || DEFAULTS_OPTIONS.currentDate,
      maxTokenAge:
        opts?.decryptOptions?.maxTokenAge ??
        DEFAULTS_OPTIONS.authorizationCode.expiresIn,
    },
    encryptOptions: {
      ...opts?.encryptOptions,
      currentDate:
        opts?.encryptOptions?.currentDate || DEFAULTS_OPTIONS.currentDate,
      expiresIn:
        opts?.encryptOptions?.expiresIn ??
        DEFAULTS_OPTIONS.authorizationCode.expiresIn,
    },
  };
}

// Refresh Token Options

export type RefreshTokenOptions = AuthorizationCodeOptions;

export type ResolvedRefreshTokenOptions = ResolvedAuthorizationCodeOptions;

/**
 * Apply defaults for the Refresh Token helpers.
 */
export function refreshTokenDefaults<T extends RefreshTokenOptions>(
  opts: T,
): ResolvedRefreshTokenOptions {
  return {
    privateKey: opts.privateKey,
    decryptOptions: {
      ...opts.decryptOptions,
      currentDate:
        opts?.decryptOptions?.currentDate || DEFAULTS_OPTIONS.currentDate,
      maxTokenAge:
        opts?.decryptOptions?.maxTokenAge ??
        DEFAULTS_OPTIONS.refreshToken.expiresIn,
    },
    encryptOptions: {
      ...opts?.encryptOptions,
      currentDate:
        opts?.encryptOptions?.currentDate || DEFAULTS_OPTIONS.currentDate,
      expiresIn:
        opts?.encryptOptions?.expiresIn ??
        DEFAULTS_OPTIONS.refreshToken.expiresIn,
    },
  };
}

// Access Token Options

export interface AccessTokenOptions {
  /**
   * The private key to sign the access token.
   */
  privateKey: JWK;
  /**
   * The public key or key set to verify the access token.
   */
  publicKey?: MaybeArray<JWK>;
  /**
   * Options for signing the access token.
   */
  signOptions?: JWSSignOptions;
  /**
   * Options for verifying the access token.
   */
  verifyOptions?: JWSVerifyOptions;
}

export type ResolvedAccessTokenOptions = Require<
  AccessTokenOptions,
  "signOptions.expiresIn" | "signOptions.currentDate"
>;

/**
 * Apply defaults for the Access Token helpers.
 */
export function accessTokenDefaults<T extends AccessTokenOptions>(
  opts: T,
): ResolvedAccessTokenOptions {
  return {
    privateKey: opts.privateKey,
    publicKey: opts.publicKey,
    verifyOptions: {
      ...opts.verifyOptions,
      currentDate:
        opts?.verifyOptions?.currentDate || DEFAULTS_OPTIONS.currentDate,
      maxTokenAge:
        opts?.verifyOptions?.maxTokenAge ??
        DEFAULTS_OPTIONS.accessToken.expiresIn,
    },
    signOptions: {
      ...opts?.signOptions,
      currentDate:
        opts?.signOptions?.currentDate || DEFAULTS_OPTIONS.currentDate,
      expiresIn:
        opts?.signOptions?.expiresIn ?? DEFAULTS_OPTIONS.accessToken.expiresIn,
    },
  };
}

// OAuth Provider Options

export interface OAuthProviderOptions {
  issuer: string;
  authorizationCodeOptions: AuthorizationCodeOptions;
  refreshTokenOptions: RefreshTokenOptions;
  accessTokenOptions: AccessTokenOptions;
  randomJti?: () => string;
}

/**
 * Apply all defaults for an OAuthProvider instance.
 */
export function oauthProviderDefaults(args: OAuthProviderOptions) {
  return {
    issuer: args.issuer,
    randomJti: args.randomJti || DEFAULTS_OPTIONS.randomJti,
    authorizationCodeOptions: authorizationCodeDefaults(
      args.authorizationCodeOptions,
    ),
    refreshTokenOptions: refreshTokenDefaults(args.refreshTokenOptions),
    accessTokenOptions: accessTokenDefaults(args.accessTokenOptions),
  };
}
