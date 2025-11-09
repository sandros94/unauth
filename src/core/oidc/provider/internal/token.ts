import { computeExpiresInSeconds } from "unjwt/utils";
import { sign } from "unjwt/jws";

import type { MaybePromise } from "../../../../types";

import type {
  Result,
  TokenSuccessResponse,
  AccessTokenClaims,
  IdTokenClaims,
  TokenErrorResponse,
  RefreshTokenClaims,
} from "../../types";
import {
  type NormalizedAuthorizationCodeGrantInput as OAuthNormalizedAuthorizationCodeGrantInput,
  type NormalizedRefreshTokenGrantInput as OAuthNormalizedRefreshTokenGrantInput,
  type NormalizedClientCredentialsGrantInput,
  type AuthorizationCodeGrantOptions as OAuthAuthorizationCodeGrantOptions,
  type RefreshTokenGrantOptions as OAuthRefreshTokenGrantOptions,
  issueAuthorizationCodeGrant as oauthIssueAuthorizationCodeGrant,
  issueRefreshTokenGrant as oauthIssueRefreshTokenGrant,
  introspectAuthorizationCode as defaultIntrospectAuthorizationCode,
  introspectRefreshToken as defaultIntrospectRefreshToken,
} from "../../../oauth";
import { type IdTokenOptions, idTokenDefaults } from "./defaults";
import { computeTokenHash } from "./utils";

export {
  type TokenGrantType,
  type NormalizedClientCredentialsGrantInput,
  type IssueClientCredentialsGrantReturn,
  validateTokenRequest,
  issueClientCredentialsGrant,
} from "../../../oauth/provider/internal/token";

// #region callback types

/**
 * Callback to sign an ID token.
 * Framework adapters can override this to use their own token handling.
 */
export type SignIdTokenCallback = (
  claims: IdTokenClaims,
) => MaybePromise<string>;

// #endregion callback types

// #region types

export interface NormalizedAuthorizationCodeGrantInput
  extends OAuthNormalizedAuthorizationCodeGrantInput {
  idTokenExtraClaims?: Record<string, unknown>;
}

export interface NormalizedRefreshTokenGrantInput
  extends OAuthNormalizedRefreshTokenGrantInput {
  idTokenExtraClaims?: Record<string, unknown>;
}

export type NormalizedTokenInput =
  | NormalizedAuthorizationCodeGrantInput
  | NormalizedRefreshTokenGrantInput
  | NormalizedClientCredentialsGrantInput;

// Authorization Code Grant Options for OIDC
export interface AuthorizationCodeGrantOptions
  extends OAuthAuthorizationCodeGrantOptions {
  idTokenOptions: IdTokenOptions;
  /**
   * Override the default ID token signing.
   * Useful for framework-specific implementations.
   */
  signIdToken?: SignIdTokenCallback;
}

// Refresh Token Grant Options for OIDC
export interface RefreshTokenGrantOptions
  extends OAuthRefreshTokenGrantOptions {
  idTokenOptions: IdTokenOptions;
  /**
   * Override the default ID token signing.
   * Useful for framework-specific implementations.
   */
  signIdToken?: SignIdTokenCallback;
}

export type IssueAuthorizationCodeGrantReturn = Result<
  TokenSuccessResponse,
  {
    accessTokenClaims: AccessTokenClaims;
    refreshTokenClaims: RefreshTokenClaims;
    idTokenClaims: IdTokenClaims;
  },
  TokenErrorResponse
>;

export type IssueRefreshTokenGrantReturn = Result<
  TokenSuccessResponse,
  {
    accessTokenClaims: AccessTokenClaims;
    refreshTokenClaims: RefreshTokenClaims;
    idTokenClaims: IdTokenClaims;
  },
  TokenErrorResponse
>;

// #endregion types

// #region payload creation

/**
 * Create ID token payload
 */
export function createIdTokenPayload(
  args: {
    iss: string;
    aud: string;
    sub: string;
    nonce?: string;
    extraClaims?: Record<string, unknown>;
  },
  _options: {
    currentDate?: Date;
    expiresIn: number;
  },
): Omit<IdTokenClaims, "iat" | "exp" | "at_hash"> {
  return {
    ...args.extraClaims,
    iss: args.iss,
    aud: args.aud,
    sub: args.sub,
    nonce: args.nonce,
  } as Omit<IdTokenClaims, "iat" | "exp" | "at_hash">;
}

/**
 * Compute at_hash and finalize ID token claims
 */
export async function finalizeIdTokenClaims(
  baseClaims: Omit<IdTokenClaims, "iat" | "exp" | "at_hash">,
  access_token: string,
  options: {
    alg: string;
    currentDate?: Date;
    expiresIn: number;
  },
): Promise<IdTokenClaims> {
  const at_hash = await computeTokenHash(access_token, options.alg);
  const currentDate = options.currentDate ?? new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);

  return {
    ...baseClaims,
    iat,
    exp: iat + options.expiresIn,
    at_hash,
  } as IdTokenClaims;
}

// #endregion payload creation

// #region token generation

/**
 * Sign ID token (default implementation)
 */
export async function defaultSignIdToken(
  claims: IdTokenClaims,
  options: IdTokenOptions & {
    currentDate?: Date;
  },
): Promise<string> {
  const opts = idTokenDefaults(options);
  const currentDate = options.currentDate ?? new Date();

  return sign(claims, opts.privateKey, {
    ...opts.signOptions,
    protectedHeader: { ...opts.signOptions.protectedHeader, typ: "id+jwt" },
    currentDate,
  });
}

// #endregion token generation

// #region grant type handlers

/**
 * Issues the `authorization_code` grant for OIDC.
 */
export async function issueAuthorizationCodeGrant(
  args: NormalizedAuthorizationCodeGrantInput,
  options: AuthorizationCodeGrantOptions,
): Promise<IssueAuthorizationCodeGrantReturn> {
  const {
    iss,
    authorizationCodeOptions,
    idTokenOptions,
    introspectAuthorizationCode = (token: string) =>
      defaultIntrospectAuthorizationCode({
        token,
        iss,
        options: authorizationCodeOptions,
      }),
    signIdToken = (claims: IdTokenClaims) =>
      defaultSignIdToken(claims, {
        ...idTokenOptions,
        currentDate: options.currentDate,
      }),
    currentDate,
  } = options;

  // Step 2: Introspect authorization code if it's a string
  const codeClaims =
    typeof args.code === "string"
      ? await introspectAuthorizationCode(args.code)
      : args.code;

  // Build OAuth tokens first
  const oauthRes = await oauthIssueAuthorizationCodeGrant(
    {
      ...args,
      code: codeClaims,
      refreshTokenExtraClaims: {
        ...args.refreshTokenExtraClaims,
        ...(codeClaims.nonce ? { nonce: codeClaims.nonce } : {}),
      },
    },
    {
      ...options,
      introspectAuthorizationCode: undefined, // Already introspected above
    },
  );

  if (!oauthRes.success) {
    return { success: false, error: oauthRes.error };
  }

  const { access_token, refresh_token, expires_in } = oauthRes.value;
  const { accessTokenClaims, refreshTokenClaims } = oauthRes.artifacts!;

  // Step 4: Create ID token payload
  const idOpts = idTokenDefaults(idTokenOptions);
  const alg = idOpts.privateKey.alg || idOpts.signOptions.alg;
  if (!alg) {
    throw new Error("[OIDC] JWS alg is required to compute at_hash");
  }

  const baseIdClaims = createIdTokenPayload(
    {
      iss,
      aud: args.client_id,
      sub: accessTokenClaims.sub,
      nonce: (codeClaims.nonce as string) || undefined,
      extraClaims: args.idTokenExtraClaims,
    },
    {
      currentDate,
      expiresIn: computeExpiresInSeconds(idOpts.signOptions.expiresIn),
    },
  );

  const idTokenClaims = await finalizeIdTokenClaims(
    baseIdClaims,
    access_token,
    {
      alg,
      currentDate,
      expiresIn: computeExpiresInSeconds(idOpts.signOptions.expiresIn),
    },
  );

  // Step 5: Sign ID token
  const id_token = await signIdToken(idTokenClaims);

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in,
      scope: accessTokenClaims.scope,
      refresh_token,
      id_token,
    },
    artifacts: {
      accessTokenClaims,
      refreshTokenClaims,
      idTokenClaims,
    },
  };
}

/**
 * Issues the `refresh_token` grant for OIDC.
 */
export async function issueRefreshTokenGrant(
  args: NormalizedRefreshTokenGrantInput,
  options: RefreshTokenGrantOptions,
): Promise<IssueRefreshTokenGrantReturn> {
  const {
    iss,
    refreshTokenOptions,
    idTokenOptions,
    introspectRefreshToken = (token: string) =>
      defaultIntrospectRefreshToken({
        token,
        iss,
        options: refreshTokenOptions,
      }),
    signIdToken = (claims: IdTokenClaims) =>
      defaultSignIdToken(claims, {
        ...idTokenOptions,
        currentDate: options.currentDate,
      }),
    currentDate,
  } = options;

  // Step 2: Introspect refresh token if it's a string
  const oldRTClaims =
    typeof args.refresh_token === "string"
      ? await introspectRefreshToken(args.refresh_token)
      : args.refresh_token;

  // Build OAuth tokens first
  const oauthRes = await oauthIssueRefreshTokenGrant(
    {
      ...args,
      refresh_token: oldRTClaims,
      refreshTokenExtraClaims: {
        ...args.refreshTokenExtraClaims,
        ...(oldRTClaims.nonce ? { nonce: oldRTClaims.nonce } : {}),
      },
    },
    {
      ...options,
      introspectRefreshToken: undefined, // Already introspected above
      currentDate,
    },
  );

  if (!oauthRes.success) {
    return { success: false, error: oauthRes.error };
  }

  const { access_token, refresh_token, expires_in, scope } = oauthRes.value;
  const { accessTokenClaims, refreshTokenClaims } = oauthRes.artifacts!;

  // Step 4: Create ID token payload
  const idOpts = idTokenDefaults(idTokenOptions);
  const alg = idOpts.privateKey.alg || idOpts.signOptions.alg;
  if (!alg) {
    throw new Error("[OIDC] JWS alg is required to compute at_hash");
  }

  const baseIdClaims = createIdTokenPayload(
    {
      iss,
      aud: args.client_id,
      sub: accessTokenClaims.sub,
      nonce: (oldRTClaims.nonce as string) || undefined,
      extraClaims: args.idTokenExtraClaims,
    },
    {
      currentDate,
      expiresIn: computeExpiresInSeconds(idOpts.signOptions.expiresIn),
    },
  );

  const idTokenClaims = await finalizeIdTokenClaims(
    baseIdClaims,
    access_token,
    {
      alg,
      currentDate,
      expiresIn: computeExpiresInSeconds(idOpts.signOptions.expiresIn),
    },
  );

  // Step 5: Sign ID token
  const id_token = await signIdToken(idTokenClaims);

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in,
      scope,
      refresh_token,
      id_token,
    },
    artifacts: {
      accessTokenClaims,
      refreshTokenClaims,
      idTokenClaims,
    },
  };
}

// #endregion grant type handlers
