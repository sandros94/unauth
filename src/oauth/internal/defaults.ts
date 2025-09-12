import type {
  JWK,
  JWEEncryptOptions,
  JWEDecryptOptions,
  JWSSignOptions,
  JWSVerifyOptions,
} from "unjwt";

import type { Require } from "../../types";
import { mergeArrays } from "../../utils";

import type { OAuthProviderHooks } from "../hooks";

export const DEFAULTS_OPTIONS = Object.freeze({
  tokenType: "Bearer" as const,
  randomJti: () => crypto.randomUUID(),
  currentDate: new Date(),
  // OAuth 2.1: if code_challenge_method is omitted, default is "plain"
  codeChallengeMethod: "plain" as const,
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

export type RefreshTokenOptions = AuthorizationCodeOptions;

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

export interface AccessTokenOptions {
  /**
   * The private key to sign the access token.
   */
  privateKey: JWK;
  /**
   * Options for signing the access token.
   */
  signOptions?: JWSSignOptions;
  /**
   * Options for verifying the access token.
   */
  verifyOptions?: JWSVerifyOptions;
}

export interface OAuthOptions {
  /**
   * The issuer identifier.
   */
  issuer: string;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * The current date to use for issued at (iat) claims. Defaults to `new Date()`.
   */
  currentDate?: Date;
  /**
   * The default code_challenge_method if not provided in the request (OAuth 2.1 suggests "S256", but specifies "plain" as default).
   */
  defaultCodeChallengeMethod?: "plain" | "S256";
  /**
   * The default authorization scope.
   */
  defaultScope?: string;
  /**
   * The default audience (aud) claim.
   */
  defaultAudience?: string;
  /**
   * Allowed scopes configuration (optional). If provided, membership will be validated.
   */
  availableScopes?: string[];
  /**
   * Authorization Code options.
   */
  authorizationCode: AuthorizationCodeOptions;
  /**
   * Refresh Token options.
   */
  refreshToken: RefreshTokenOptions;
  /**
   * Access Token options.
   */
  accessToken: AccessTokenOptions;
  hooks: OAuthProviderHooks;
}

export type ResolvedAuthorizationCodeOptions = Require<
  AuthorizationCodeOptions,
  "encryptOptions.expiresIn" | "encryptOptions.currentDate"
>;

export type ResolvedRefreshTokenOptions = ResolvedAuthorizationCodeOptions;

export type ResolvedAccessTokenOptions = Require<
  AccessTokenOptions,
  "signOptions.expiresIn" | "signOptions.currentDate"
>;

export type ResolvedOAuthOptions = Require<
  Omit<OAuthOptions, "authorizationCode" | "refreshToken" | "accessToken">,
  "randomJti" | "currentDate" | "defaultCodeChallengeMethod"
> & {
  authorizationCode: ResolvedAuthorizationCodeOptions;
  refreshToken: ResolvedRefreshTokenOptions;
  accessToken: ResolvedAccessTokenOptions;
};

/**
 * Apply defaults for the Authorization Code helpers.
 */
export function authorizationCodeDefaults<T extends AuthorizationCodeOptions>(
  opts: T,
): ResolvedAuthorizationCodeOptions {
  return {
    privateKey: opts.privateKey,
    decryptOptions: opts.decryptOptions,
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

/**
 * Apply defaults for the Refresh Token helpers.
 */
export function refreshTokenDefaults<T extends RefreshTokenOptions>(
  opts: T,
): ResolvedRefreshTokenOptions {
  return {
    privateKey: opts.privateKey,
    decryptOptions: opts.decryptOptions,
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

/**
 * Apply defaults for the Access Token helpers.
 */
export function accessTokenDefaults<T extends AccessTokenOptions>(
  opts: T,
): ResolvedAccessTokenOptions {
  return {
    privateKey: opts.privateKey,
    verifyOptions: opts.verifyOptions,
    signOptions: {
      ...opts?.signOptions,
      currentDate:
        opts?.signOptions?.currentDate || DEFAULTS_OPTIONS.currentDate,
      expiresIn:
        opts?.signOptions?.expiresIn ?? DEFAULTS_OPTIONS.accessToken.expiresIn,
    },
  };
}

export function oauthOptionsDefaults<T extends OAuthOptions>(
  opts: T,
): ResolvedOAuthOptions {
  const authorizationCode = authorizationCodeDefaults({
    ...opts.authorizationCode,
    encryptOptions: {
      ...opts.authorizationCode?.encryptOptions,
      currentDate: opts.currentDate || DEFAULTS_OPTIONS.currentDate,
    },
  });
  const refreshToken = refreshTokenDefaults({
    ...opts.refreshToken,
    encryptOptions: {
      ...opts.refreshToken?.encryptOptions,
      currentDate: opts.currentDate || DEFAULTS_OPTIONS.currentDate,
    },
  });
  const accessToken = accessTokenDefaults({
    ...opts.accessToken,
    signOptions: {
      ...opts.accessToken?.signOptions,
      currentDate: opts.currentDate || DEFAULTS_OPTIONS.currentDate,
    },
  });

  const availableScopes = mergeArrays(
    opts.availableScopes || [],
    opts.defaultScope?.split(" ") || [],
  );

  return {
    issuer: opts.issuer,
    randomJti: opts.randomJti || DEFAULTS_OPTIONS.randomJti,
    currentDate: opts.currentDate || DEFAULTS_OPTIONS.currentDate,
    defaultScope: opts.defaultScope,
    defaultCodeChallengeMethod:
      opts.defaultCodeChallengeMethod || DEFAULTS_OPTIONS.codeChallengeMethod,
    availableScopes,
    authorizationCode,
    refreshToken,
    accessToken,
    hooks: opts.hooks
  };
}
