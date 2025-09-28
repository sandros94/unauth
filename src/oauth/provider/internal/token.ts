import { computeExpiresInSeconds } from "unjwt/utils";
import type { JWTClaims } from "unjwt";
import { encrypt } from "unjwt/jwe";
import { sign } from "unjwt/jws";

import type {
  TokenRequest,
  AuthorizationCodeClaims,
  AccessTokenClaims,
  RefreshTokenClaims,
  AuthorizationCodeGrantRequest,
  ClientCredentialsGrantRequest,
  RefreshTokenGrantRequest,
  TokenSuccessResponse,
} from "../../types";

import { OAuthError } from "../error";
import {
  type AccessTokenOptions,
  type RefreshTokenOptions,
  accessTokenDefaults,
  refreshTokenDefaults,
} from "./defaults";
import { isScopeSubset, validatePKCE } from "./utils";

// #region type definitions

/**
 * Arguments for handling the `authorization_code` grant flow.
 */
export interface BuildAuthorizationCodeGrantArgs {
  req: AuthorizationCodeGrantRequest;
  codeClaims: AuthorizationCodeClaims;
  accessTokenOptions: AccessTokenOptions;
  refreshTokenOptions: RefreshTokenOptions;
  extraAccessTokenClaims?: JWTClaims;
  extraRefreshTokenClaims?: JWTClaims;
  /**
   * Issuer to include in error responses (if any).
   */
  iss: string;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * Date of the request (for expiration, etc.).
   */
  currentDate?: Date;
}

/**
 * Return values from handling the `authorization_code` grant flow.
 */
export interface BuildAuthorizationCodeGrantReturn {
  res: TokenSuccessResponse;
  accessTokenClaims: AccessTokenClaims;
  refreshTokenClaims: RefreshTokenClaims;
}

/**
 * Arguments for handling the `client_credentials` grant flow.
 */
export interface BuildClientCredentialsGrantArgs {
  req: ClientCredentialsGrantRequest;
  accessTokenOptions: AccessTokenOptions;
  extraAccessTokenClaims?: JWTClaims;
  /**
   * Issuer to include in error responses (if any).
   */
  iss: string;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * Date of the request (for expiration, etc.).
   */
  currentDate?: Date;
}

/**
 * Return values from handling the `client_credentials` grant flow.
 */
export interface BuildClientCredentialsGrantReturn {
  res: TokenSuccessResponse;
  accessTokenClaims: AccessTokenClaims;
}

/**
 * Arguments for handling the `refresh_token` grant flow.
 */
export interface BuildRefreshTokenGrantArgs {
  req: RefreshTokenGrantRequest;
  refreshTokenClaims: RefreshTokenClaims;
  accessTokenOptions: AccessTokenOptions;
  refreshTokenOptions: RefreshTokenOptions;
  extraAccessTokenClaims?: JWTClaims;
  extraRefreshTokenClaims?: JWTClaims;
  /**
   * Issuer to include in error responses (if any).
   */
  iss: string;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * Date of the request (for expiration, etc.).
   */
  currentDate?: Date;
}

/**
 * Return values from handling the `refresh_token` grant flow.
 */
export interface BuildRefreshTokenGrantReturn {
  res: TokenSuccessResponse;
  accessTokenClaims: AccessTokenClaims;
  refreshTokenClaims: RefreshTokenClaims;
}

// #endregion type definitions

// #region validation functions

function isTokenRequest(value: unknown): value is TokenRequest {
  if (typeof value !== "object" || value == null) return false;
  const v = value as TokenRequest;

  // Only check for `grant_type` presence and type here.
  return (
    typeof v.grant_type === "string" &&
    ["authorization_code", "refresh_token", "client_credentials"].includes(
      v.grant_type,
    )
  );
}

function isAuthorizationCodeGrantRequest(
  value: TokenRequest,
): value is AuthorizationCodeGrantRequest {
  return value.grant_type === "authorization_code";
}

function isClientCredentialsGrantRequest(
  value: TokenRequest,
): value is ClientCredentialsGrantRequest {
  return value.grant_type === "client_credentials";
}

function isRefreshTokenGrantRequest(
  value: TokenRequest,
): value is RefreshTokenGrantRequest {
  return value.grant_type === "refresh_token";
}

export function validateAuthorizationCodeGrantRequest(
  req: AuthorizationCodeGrantRequest,
  iss: string,
): void {
  if (!req.code || typeof req.code !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing authorization code",
      iss,
    });
  }

  if (!req.client_id || typeof req.client_id !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing or invalid client_id",
      iss,
    });
  }

  if (!req.code_verifier || typeof req.code_verifier !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing PKCE code_verifier",
      iss,
    });
  }

  return;
}

export function validateClientCredentialsGrantRequest(
  req: ClientCredentialsGrantRequest,
  iss: string,
): void {
  if (!req.client_id || typeof req.client_id !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing or invalid client_id",
      iss,
    });
  }

  if (
    !req.resource ||
    (Array.isArray(req.resource) && req.resource.length === 0)
  ) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing resource in client_credentials request",
      iss,
    });
  }

  if ("scope" in req && req.scope != null && typeof req.scope !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Invalid scope type",
      iss,
    });
  }

  return;
}

export function validateRefreshTokenGrantRequest(
  req: RefreshTokenGrantRequest,
  iss: string,
): void {
  if (!req.refresh_token || typeof req.refresh_token !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing refresh_token",
      iss,
    });
  }

  if (!req.client_id || typeof req.client_id !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing or invalid client_id",
      iss,
    });
  }

  if ("scope" in req && req.scope != null && typeof req.scope !== "string") {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Invalid scope type",
      iss,
    });
  }

  return;
}

export function validateTokenRequest(
  req: unknown,
  iss: string,
): asserts req is TokenRequest {
  if (!isTokenRequest(req)) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Invalid token request",
      iss,
    });
  }

  if (
    isAuthorizationCodeGrantRequest(req) ||
    isClientCredentialsGrantRequest(req) ||
    isRefreshTokenGrantRequest(req)
  ) {
    return;
  }

  throw new OAuthError({
    error: "unsupported_grant_type",
    error_description: `Unsupported grant_type: ${(req as TokenRequest).grant_type}`,
    iss,
  });
}

export async function validateAuthorizationCodeClaims(args: {
  claims: AuthorizationCodeClaims;
  req: AuthorizationCodeGrantRequest;
  iss: string;
}): Promise<void> {
  const { claims, req, iss } = args;

  if (!claims || !("sub" in claims) || !claims.sub) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Invalid authorization code: missing subject (sub)",
      iss,
    });
  }

  if (claims.client_id !== req.client_id) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Authorization code was issued to a different client",
      iss,
    });
  }

  // TODO: Per RFC 8707, resource maps to aud, but RFC 9068 is both required but also accept a fallback registered for the client?
  const aud = claims.resource;
  if (!aud || (Array.isArray(aud) && aud.length === 0)) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Missing resource in authorization code",
      iss,
    });
  }

  if (!claims.code_challenge || !claims.code_challenge_method) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing code_challenge in authorization session",
      iss,
    });
  }

  if (
    claims.code_challenge_method !== "plain" &&
    claims.code_challenge_method !== "S256"
  ) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Unsupported code_challenge_method",
      iss,
    });
  }

  const pkceIsValid = await validatePKCE(
    req.code_verifier,
    claims.code_challenge,
    claims.code_challenge_method,
  );

  if (!pkceIsValid) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Invalid PKCE code_verifier",
      iss,
    });
  }
}

export async function validateRefreshTokenClaims(args: {
  claims: RefreshTokenClaims;
  req: RefreshTokenGrantRequest;
  iss: string;
}): Promise<void> {
  const { claims, req, iss } = args;

  if (!claims || !("sub" in claims) || !claims.sub) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Invalid refresh token: missing subject (sub)",
      iss,
    });
  }

  if (!claims.client_id) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Invalid refresh token: missing client binding",
      iss,
    });
  }

  // 2. Validate client binding
  if (req.client_id && claims.client_id !== req.client_id) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Refresh token was issued to a different client",
      iss,
    });
  }

  // 3. Validate scope
  const originalScope = claims.scope;
  const requestedScope = req.scope;
  if (
    requestedScope &&
    originalScope &&
    !isScopeSubset(requestedScope, originalScope)
  ) {
    throw new OAuthError({
      error: "invalid_scope",
      error_description: "Requested scope exceeds original grant",
      iss,
    });
  }

  // TODO: Per RFC 8707, resource maps to aud, but RFC 9068 is both required but also accept a fallback registered for the client?
  const aud = claims.resource;
  if (!aud || (Array.isArray(aud) && aud.length === 0)) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Missing resource in authorization code",
      iss,
    });
  }
}

// #endregion validation functions

// #region Grant-Specific Builders

/**
 * Builds the `authorization_code` grant flow.
 */
export async function buildAuthorizationCodeGrant(
  args: BuildAuthorizationCodeGrantArgs,
): Promise<BuildAuthorizationCodeGrantReturn> {
  const {
    req,
    codeClaims,
    accessTokenOptions,
    refreshTokenOptions,
    iss,
    extraAccessTokenClaims,
    extraRefreshTokenClaims,
  } = args;

  validateTokenRequest(req, iss);
  validateAuthorizationCodeGrantRequest(req, iss);

  await validateAuthorizationCodeClaims({
    claims: codeClaims,
    req,
    iss,
  });

  const atOpts = accessTokenDefaults(accessTokenOptions);
  const rtOpts = refreshTokenDefaults(refreshTokenOptions);

  const randomJti = args.randomJti || crypto.randomUUID;
  const currentDate =
    (args.currentDate ||
      atOpts.signOptions.currentDate ||
      rtOpts.encryptOptions.currentDate) ??
    new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);
  const expiresIn = computeExpiresInSeconds(atOpts.signOptions.expiresIn);

  const atClaims: AccessTokenClaims = {
    ...extraAccessTokenClaims,
    jti: randomJti(),
    iss,
    sub: codeClaims.sub,
    aud: codeClaims.resource,
    exp: iat + expiresIn,
    iat,
    client_id: req.client_id,
    scope: codeClaims.scope,
  };

  const rtClaims: RefreshTokenClaims = {
    ...extraRefreshTokenClaims,
    jti: randomJti(),
    iss,
    sub: codeClaims.sub,
    exp: iat + computeExpiresInSeconds(rtOpts.encryptOptions.expiresIn),
    iat,
    client_id: req.client_id,
    resource: codeClaims.resource,
    scope: codeClaims.scope,
  };

  const [access_token, refresh_token] = await Promise.all([
    sign(atClaims, atOpts.privateKey, {
      ...atOpts.signOptions,
      protectedHeader: { ...atOpts.signOptions.protectedHeader, typ: "at+jwt" },
      currentDate,
    }),
    encrypt(rtClaims, rtOpts.privateKey, {
      ...rtOpts.encryptOptions,
      protectedHeader: {
        ...rtOpts.encryptOptions.protectedHeader,
        typ: "rt+jwt",
      },
      currentDate,
    }),
  ]);

  return {
    res: {
      access_token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope: atClaims.scope,
      refresh_token,
    },
    accessTokenClaims: atClaims,
    refreshTokenClaims: rtClaims,
  };
}

/**
 * Builds the `client_credentials` grant flow.
 */
export async function buildClientCredentialsGrant(
  args: BuildClientCredentialsGrantArgs,
): Promise<BuildClientCredentialsGrantReturn> {
  const { req, accessTokenOptions, extraAccessTokenClaims, iss } = args;

  validateTokenRequest(req, iss);
  validateClientCredentialsGrantRequest(req, iss);

  const atOpts = accessTokenDefaults(accessTokenOptions);

  const randomJti = args.randomJti || crypto.randomUUID;
  const currentDate =
    (args.currentDate || atOpts.signOptions.currentDate) ?? new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);
  const expiresIn = computeExpiresInSeconds(atOpts.signOptions.expiresIn);

  const atClaims: AccessTokenClaims = {
    ...extraAccessTokenClaims,
    jti: randomJti(),
    iss,
    sub: req.client_id,
    aud: req.resource,
    exp: iat + expiresIn,
    iat,
    client_id: req.client_id,
    scope: req.scope,
  };

  const access_token = await sign(atClaims, atOpts.privateKey, {
    ...atOpts.signOptions,
    protectedHeader: { ...atOpts.signOptions.protectedHeader, typ: "at+jwt" },
    currentDate,
  });

  return {
    res: {
      access_token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope: atClaims.scope,
    },
    accessTokenClaims: atClaims,
  };
}

/**
 * Builds the `refresh_token` grant flow.
 */
export async function buildRefreshTokenGrant(
  args: BuildRefreshTokenGrantArgs,
): Promise<BuildRefreshTokenGrantReturn> {
  const {
    req,
    refreshTokenClaims,
    accessTokenOptions,
    refreshTokenOptions,
    extraAccessTokenClaims,
    extraRefreshTokenClaims,
    iss,
  } = args;

  validateTokenRequest(req, iss);
  validateRefreshTokenGrantRequest(req, iss);

  await validateRefreshTokenClaims({
    claims: refreshTokenClaims,
    req,
    iss,
  });

  const atOpts = accessTokenDefaults(accessTokenOptions);
  const rtOpts = refreshTokenDefaults(refreshTokenOptions);

  // 5. Build new tokens (implementing refresh token rotation)
  const randomJti = args.randomJti || crypto.randomUUID;
  const currentDate =
    (args.currentDate ||
      atOpts.signOptions.currentDate ||
      rtOpts.encryptOptions.currentDate) ??
    new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);
  const expiresIn = computeExpiresInSeconds(atOpts.signOptions.expiresIn);
  const newScope = req.scope || refreshTokenClaims.scope;

  const newAccessTokenClaims: AccessTokenClaims = {
    ...extraAccessTokenClaims,
    jti: randomJti(),
    iss,
    sub: refreshTokenClaims.sub,
    aud: refreshTokenClaims.resource,
    exp: iat + expiresIn,
    iat,
    client_id: refreshTokenClaims.client_id,
    scope: newScope,
  };

  const newRefreshTokenClaims: RefreshTokenClaims = {
    ...extraRefreshTokenClaims,
    jti: randomJti(),
    iss,
    sub: refreshTokenClaims.sub,
    exp: iat + computeExpiresInSeconds(rtOpts.encryptOptions.expiresIn),
    iat,
    client_id: refreshTokenClaims.client_id,
    resource: refreshTokenClaims.resource,
    scope: newScope, // The new refresh token carries the potentially narrowed scope
  };

  const [access_token, new_refresh_token] = await Promise.all([
    sign(newAccessTokenClaims, atOpts.privateKey, {
      ...atOpts.signOptions,
      protectedHeader: { ...atOpts.signOptions.protectedHeader, typ: "at+jwt" },
      currentDate,
    }),
    encrypt(newRefreshTokenClaims, rtOpts.privateKey, {
      ...rtOpts.encryptOptions,
      protectedHeader: {
        ...rtOpts.encryptOptions.protectedHeader,
        typ: "rt+jwt",
      },
      currentDate,
    }),
  ]);

  return {
    res: {
      access_token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope: newScope,
      refresh_token: new_refresh_token,
    },
    accessTokenClaims: newAccessTokenClaims,
    refreshTokenClaims: newRefreshTokenClaims,
  };
}

// #endregion Grant-Specific Builders
