import { computeExpiresInSeconds } from "unjwt/utils";
import { encrypt } from "unjwt/jwe";
import { sign } from "unjwt/jws";

import type { MaybePromise } from "../../../../types";

import type {
  Result,
  TokenRequest,
  TokenErrorCode,
  TokenErrorResponse,
  TokenSuccessResponse,
  AuthorizationCodeClaims,
  AccessTokenClaims,
  RefreshTokenClaims,
  AuthorizationCodeGrantRequest,
  ClientCredentialsGrantRequest,
  RefreshTokenGrantRequest,
} from "../../types";

import { OAuthError } from "../error";
import {
  type AuthorizationCodeOptions,
  type AccessTokenOptions,
  type RefreshTokenOptions,
  accessTokenDefaults,
  refreshTokenDefaults,
} from "./defaults";
import {
  introspectAuthorizationCode as defaultIntrospectAuthorizationCode,
  introspectRefreshToken as defaultIntrospectRefreshToken,
} from "./introspect";
import { isScopeSubset, validatePKCE } from "./utils";

// #region callback types

/**
 * Callback to introspect an authorization code token.
 * Framework adapters can override this to use their own token handling.
 */
export type IntrospectAuthorizationCodeCallback = (
  token: string,
) => MaybePromise<AuthorizationCodeClaims>;

/**
 * Callback to introspect a refresh token.
 * Framework adapters can override this to use their own token handling.
 */
export type IntrospectRefreshTokenCallback = (
  token: string,
) => MaybePromise<RefreshTokenClaims>;

/**
 * Callback to sign an access token.
 * Framework adapters can override this to use their own token handling.
 */
export type SignAccessTokenCallback = (
  claims: AccessTokenClaims,
) => MaybePromise<string>;

/**
 * Callback to encrypt a refresh token.
 * Framework adapters can override this to use their own token handling.
 */
export type EncryptRefreshTokenCallback = (
  claims: RefreshTokenClaims,
) => MaybePromise<string>;

// #endregion callback types

// #region types

export type TokenGrantType =
  | "authorization_code"
  | "refresh_token"
  | "client_credentials";

export interface NormalizedAuthorizationCodeGrantInput {
  grant_type: "authorization_code";
  client_id: string;
  client_secret?: undefined;
  code: string | AuthorizationCodeClaims;
  code_verifier: string;
  accessTokenExtraClaims?: Record<string, unknown>;
  refreshTokenExtraClaims?: Record<string, unknown>;
}

export interface NormalizedClientCredentialsGrantInput {
  grant_type: "client_credentials";
  client_id: string;
  client_secret: string;
  resource: string | string[];
  scope?: string;
  accessTokenExtraClaims?: Record<string, unknown>;
}

export interface NormalizedRefreshTokenGrantInput {
  grant_type: "refresh_token";
  client_id: string;
  client_secret?: undefined;
  refresh_token: string | RefreshTokenClaims;
  requested_scope?: string;
  accessTokenExtraClaims?: Record<string, unknown>;
  refreshTokenExtraClaims?: Record<string, unknown>;
}

export type NormalizedTokenInput =
  | NormalizedAuthorizationCodeGrantInput
  | NormalizedRefreshTokenGrantInput
  | NormalizedClientCredentialsGrantInput;

// Common options for all grant types
export interface BaseTokenGrantOptions {
  iss: string;
  accessTokenOptions: AccessTokenOptions;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * Date to use when computing NumericDate claims, defaults to `new Date()`.
   */
  currentDate?: Date;
}

// Authorization Code Grant Options
export interface AuthorizationCodeGrantOptions extends BaseTokenGrantOptions {
  authorizationCodeOptions: AuthorizationCodeOptions;
  refreshTokenOptions: RefreshTokenOptions;
  /**
   * Override the default authorization code introspection.
   * Useful for framework-specific implementations.
   */
  introspectAuthorizationCode?: IntrospectAuthorizationCodeCallback;
  /**
   * Override the default access token signing.
   * Useful for framework-specific implementations.
   */
  signAccessToken?: SignAccessTokenCallback;
  /**
   * Override the default refresh token encryption.
   * Useful for framework-specific implementations.
   */
  encryptRefreshToken?: EncryptRefreshTokenCallback;
}

// Client Credentials Grant Options
export interface ClientCredentialsGrantOptions extends BaseTokenGrantOptions {
  /**
   * Override the default access token signing.
   * Useful for framework-specific implementations.
   */
  signAccessToken?: SignAccessTokenCallback;
}

// Refresh Token Grant Options
export interface RefreshTokenGrantOptions extends BaseTokenGrantOptions {
  refreshTokenOptions: RefreshTokenOptions;
  /**
   * Override the default refresh token introspection.
   * Useful for framework-specific implementations.
   */
  introspectRefreshToken?: IntrospectRefreshTokenCallback;
  /**
   * Override the default access token signing.
   * Useful for framework-specific implementations.
   */
  signAccessToken?: SignAccessTokenCallback;
  /**
   * Override the default refresh token encryption.
   * Useful for framework-specific implementations.
   */
  encryptRefreshToken?: EncryptRefreshTokenCallback;
}

export type IssueAuthorizationCodeGrantReturn = Result<
  TokenSuccessResponse,
  {
    accessTokenClaims: AccessTokenClaims;
    refreshTokenClaims: RefreshTokenClaims;
  },
  TokenErrorResponse
>;

export type IssueClientCredentialsGrantReturn = Result<
  TokenSuccessResponse,
  {
    accessTokenClaims: AccessTokenClaims;
  },
  TokenErrorResponse
>;

export type IssueRefreshTokenGrantReturn = Result<
  TokenSuccessResponse,
  {
    accessTokenClaims: AccessTokenClaims;
    refreshTokenClaims: RefreshTokenClaims;
  },
  TokenErrorResponse
>;

// #endregion types

// #region internals

function tokenError(
  code: TokenErrorCode | (string & {}),
  description: string,
  details: Omit<TokenErrorResponse, "error" | "error_description"> & {
    cause?: unknown;
  } = {},
): TokenErrorResponse {
  return new OAuthError({
    ...details,
    error: code,
    error_description: description,
  }).toJSON();
}

function isTokenRequest(req: unknown): req is TokenRequest {
  if (typeof req !== "object" || req == null) return false;
  const v = req as TokenRequest;

  // Only check for `grant_type` presence here.
  return typeof v.grant_type === "string";
}

function isAuthorizationCodeGrantRequest(
  req: TokenRequest,
): req is AuthorizationCodeGrantRequest {
  return req.grant_type === "authorization_code";
}

function isClientCredentialsGrantRequest(
  req: TokenRequest,
): req is ClientCredentialsGrantRequest {
  return req.grant_type === "client_credentials";
}

function isRefreshTokenGrantRequest(
  req: TokenRequest,
): req is RefreshTokenGrantRequest {
  return req.grant_type === "refresh_token";
}

// #endregion internals

// #region validation steps

/**
 * Step 1: Validate the token request structure
 */
export function validateTokenRequest(
  req: TokenRequest & {
    accessTokenExtraClaims?: Record<string, unknown>;
    refreshTokenExtraClaims?: Record<string, unknown>;
  },
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Result<NormalizedTokenInput, undefined, TokenErrorResponse> {
  if (!isTokenRequest(req)) {
    return {
      success: false,
      error: tokenError(
        "invalid_request",
        "Invalid token request",
        errorDetails,
      ),
    };
  }

  if (!req.client_id || typeof req.client_id !== "string") {
    return {
      success: false,
      error: tokenError(
        "invalid_request",
        "Missing or invalid client_id",
        errorDetails,
      ),
    };
  }

  if (isAuthorizationCodeGrantRequest(req)) {
    return validateAuthorizationCodeGrantRequest(
      {
        grant_type: "authorization_code",
        client_id: req.client_id,
        code: req.code,
        code_verifier: req.code_verifier,
        accessTokenExtraClaims: req.accessTokenExtraClaims,
        refreshTokenExtraClaims: req.refreshTokenExtraClaims,
      },
      errorDetails,
    );
  }

  if (isClientCredentialsGrantRequest(req)) {
    return validateClientCredentialsGrantRequest(
      {
        grant_type: "client_credentials",
        client_id: req.client_id,
        client_secret: req.client_secret,
        resource: req.resource,
        scope: req.scope,
        accessTokenExtraClaims: req.accessTokenExtraClaims,
      },
      errorDetails,
    );
  }

  if (isRefreshTokenGrantRequest(req)) {
    return validateRefreshTokenGrantRequest(
      {
        grant_type: "refresh_token",
        client_id: req.client_id,
        refresh_token: req.refresh_token,
        requested_scope: req.scope,
        accessTokenExtraClaims: req.accessTokenExtraClaims,
        refreshTokenExtraClaims: req.refreshTokenExtraClaims,
      },
      errorDetails,
    );
  }

  return {
    success: false,
    error: tokenError(
      "unsupported_grant_type",
      `Unsupported grant_type: ${(req as TokenRequest).grant_type}`,
      errorDetails,
    ),
  };
}

function validateAuthorizationCodeGrantRequest(
  input: NormalizedAuthorizationCodeGrantInput,
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Result<
  NormalizedAuthorizationCodeGrantInput,
  undefined,
  TokenErrorResponse
> {
  if (
    !input.code ||
    (typeof input.code !== "string" && typeof input.code !== "object")
  ) {
    return {
      success: false,
      error: tokenError(
        "invalid_request",
        "Missing authorization code",
        errorDetails,
      ),
    };
  }

  if (!input.code_verifier || typeof input.code_verifier !== "string") {
    return {
      success: false,
      error: tokenError(
        "invalid_request",
        "Missing PKCE code_verifier",
        errorDetails,
      ),
    };
  }

  return {
    success: true,
    value: input,
  };
}

function validateClientCredentialsGrantRequest(
  input: NormalizedClientCredentialsGrantInput,
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Result<
  NormalizedClientCredentialsGrantInput,
  undefined,
  TokenErrorResponse
> {
  if (
    !input.resource ||
    (Array.isArray(input.resource) && input.resource.length === 0)
  ) {
    return {
      success: false,
      error: tokenError("invalid_request", "Missing resource", errorDetails),
    };
  }

  if (
    "scope" in input &&
    input.scope != null &&
    typeof input.scope !== "string"
  ) {
    return {
      success: false,
      error: tokenError("invalid_request", "Invalid scope type", errorDetails),
    };
  }

  return {
    success: true,
    value: input,
  };
}

function validateRefreshTokenGrantRequest(
  input: NormalizedRefreshTokenGrantInput,
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Result<NormalizedRefreshTokenGrantInput, undefined, TokenErrorResponse> {
  if (
    !input.refresh_token ||
    (typeof input.refresh_token !== "string" &&
      typeof input.refresh_token !== "object")
  ) {
    return {
      success: false,
      error: tokenError(
        "invalid_request",
        "Missing refresh_token",
        errorDetails,
      ),
    };
  }

  return {
    success: true,
    value: input,
  };
}

/**
 * Step 3: Validate authorization code claims
 */
export async function validateAuthorizationCodeClaims(
  claims: AuthorizationCodeClaims,
  input: NormalizedAuthorizationCodeGrantInput,
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Promise<Result<AuthorizationCodeClaims, undefined, TokenErrorResponse>> {
  if (!claims || !("sub" in claims) || !claims.sub) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Invalid authorization code: missing subject (sub)",
        errorDetails,
      ),
    };
  }

  if (claims.client_id !== input.client_id) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Authorization code was issued to a different client",
        errorDetails,
      ),
    };
  }

  const aud = claims.resource;
  if (!aud || (Array.isArray(aud) && aud.length === 0)) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Missing resource in authorization code",
        errorDetails,
      ),
    };
  }

  if (!claims.code_challenge || !claims.code_challenge_method) {
    return {
      success: false,
      error: tokenError(
        "invalid_request",
        "Missing PKCE code_challenge or code_challenge_method in authorization code",
        errorDetails,
      ),
    };
  }

  if (
    claims.code_challenge_method !== "plain" &&
    claims.code_challenge_method !== "S256"
  ) {
    return {
      success: false,
      error: tokenError(
        "invalid_request",
        "Unsupported code_challenge_method in authorization code",
        errorDetails,
      ),
    };
  }

  const pkceIsValid = await validatePKCE(
    input.code_verifier,
    claims.code_challenge,
    claims.code_challenge_method,
  );

  if (!pkceIsValid) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Invalid PKCE code_verifier",
        errorDetails,
      ),
    };
  }

  return { success: true, value: claims };
}

/**
 * Step 3: Validate refresh token claims
 */
export async function validateRefreshTokenClaims(
  claims: RefreshTokenClaims,
  input: NormalizedRefreshTokenGrantInput,
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Promise<Result<RefreshTokenClaims, undefined, TokenErrorResponse>> {
  if (!claims || !("sub" in claims) || !claims.sub) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Invalid refresh token: missing subject (sub)",
        errorDetails,
      ),
    };
  }

  if (!claims.client_id) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Invalid refresh token: missing client binding",
        errorDetails,
      ),
    };
  }

  if (input.client_id && claims.client_id !== input.client_id) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Refresh token was issued to a different client",
        errorDetails,
      ),
    };
  }

  const originalScope = claims.scope;
  const requestedScope = input.requested_scope;
  if (
    requestedScope &&
    originalScope &&
    !isScopeSubset(requestedScope, originalScope)
  ) {
    return {
      success: false,
      error: tokenError(
        "invalid_scope",
        "Requested scope exceeds original grant",
        errorDetails,
      ),
    };
  }

  const aud = claims.resource;
  if (!aud || (Array.isArray(aud) && aud.length === 0)) {
    return {
      success: false,
      error: tokenError(
        "invalid_grant",
        "Missing resource in refresh token",
        errorDetails,
      ),
    };
  }

  return { success: true, value: claims };
}

// #endregion validation steps

// #region payload creation steps

/**
 * Step 4: Create access token payload
 */
export function createAccessTokenPayload(
  args: {
    iss: string;
    sub: string;
    aud: string | string[];
    client_id: string;
    scope?: string;
    extraClaims?: Record<string, unknown>;
  },
  options: {
    randomJti?: () => string;
    currentDate?: Date;
    expiresIn: number;
  },
): AccessTokenClaims {
  const randomJti = options.randomJti || crypto.randomUUID;
  const currentDate = options.currentDate ?? new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);

  return {
    ...args.extraClaims,
    jti: randomJti(),
    iss: args.iss,
    sub: args.sub,
    aud: args.aud,
    exp: iat + options.expiresIn,
    iat,
    client_id: args.client_id,
    scope: args.scope,
  };
}

/**
 * Step 4: Create refresh token payload
 */
export function createRefreshTokenPayload(
  args: {
    iss: string;
    sub: string;
    client_id: string;
    resource: string | string[];
    scope?: string;
    extraClaims?: Record<string, unknown>;
  },
  options: {
    randomJti?: () => string;
    currentDate?: Date;
    expiresIn: number;
  },
): RefreshTokenClaims {
  const randomJti = options.randomJti || crypto.randomUUID;
  const currentDate = options.currentDate ?? new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);

  return {
    ...args.extraClaims,
    jti: randomJti(),
    iss: args.iss,
    sub: args.sub,
    exp: iat + options.expiresIn,
    iat,
    client_id: args.client_id,
    resource: args.resource,
    scope: args.scope,
  };
}

// #endregion payload creation steps

// #region token generation steps

/**
 * Step 5: Sign access token (default implementation)
 */
export async function defaultSignAccessToken(
  claims: AccessTokenClaims,
  options: AccessTokenOptions & {
    currentDate?: Date;
  },
): Promise<string> {
  const atOpts = accessTokenDefaults(options);
  const currentDate = options.currentDate ?? new Date();

  return sign(claims, atOpts.privateKey, {
    ...atOpts.signOptions,
    protectedHeader: { ...atOpts.signOptions.protectedHeader, typ: "at+jwt" },
    currentDate,
  });
}

/**
 * Step 5: Encrypt refresh token (default implementation)
 */
export async function defaultEncryptRefreshToken(
  claims: RefreshTokenClaims,
  options: RefreshTokenOptions & {
    currentDate?: Date;
  },
): Promise<string> {
  const rtOpts = refreshTokenDefaults(options);
  const currentDate = options.currentDate ?? new Date();

  return encrypt(claims, rtOpts.privateKey, {
    ...rtOpts.encryptOptions,
    protectedHeader: {
      ...rtOpts.encryptOptions.protectedHeader,
      typ: "rt+jwt",
    },
    currentDate,
  });
}

// #endregion token generation steps

// #region grant type handlers

/**
 * Issues the `authorization_code` grant.
 */
export async function issueAuthorizationCodeGrant(
  args: NormalizedAuthorizationCodeGrantInput,
  options: AuthorizationCodeGrantOptions,
): Promise<IssueAuthorizationCodeGrantReturn> {
  const {
    iss,
    authorizationCodeOptions,
    accessTokenOptions,
    refreshTokenOptions,
    introspectAuthorizationCode = (token: string) =>
      defaultIntrospectAuthorizationCode({
        token,
        iss,
        options: authorizationCodeOptions,
      }),
    signAccessToken = (claims: AccessTokenClaims) =>
      defaultSignAccessToken(claims, {
        ...accessTokenOptions,
        currentDate: options.currentDate,
      }),
    encryptRefreshToken = (claims: RefreshTokenClaims) =>
      defaultEncryptRefreshToken(claims, {
        ...refreshTokenOptions,
        currentDate: options.currentDate,
      }),
    randomJti,
    currentDate,
  } = options;

  // Step 2: Introspect authorization code if it's a string
  const codeClaims =
    typeof args.code === "string"
      ? await introspectAuthorizationCode(args.code)
      : args.code;

  // Step 3: Validate claims
  const validatedClaims = await validateAuthorizationCodeClaims(
    codeClaims,
    args,
  );

  if (!validatedClaims.success) {
    return { success: false, error: validatedClaims.error };
  }

  const validClaims = validatedClaims.value;
  const atOpts = accessTokenDefaults(accessTokenOptions);
  const rtOpts = refreshTokenDefaults(refreshTokenOptions);

  // Step 4: Create token payloads
  const atClaims = createAccessTokenPayload(
    {
      iss,
      sub: validClaims.sub,
      aud: validClaims.resource,
      client_id: validClaims.client_id,
      scope: validClaims.scope,
      extraClaims: args.accessTokenExtraClaims,
    },
    {
      randomJti,
      currentDate,
      expiresIn: computeExpiresInSeconds(atOpts.signOptions.expiresIn),
    },
  );

  const rtClaims = createRefreshTokenPayload(
    {
      iss,
      sub: validClaims.sub,
      client_id: validClaims.client_id,
      resource: validClaims.resource,
      scope: validClaims.scope,
      extraClaims: args.refreshTokenExtraClaims,
    },
    {
      randomJti,
      currentDate,
      expiresIn: computeExpiresInSeconds(rtOpts.encryptOptions.expiresIn),
    },
  );

  // Step 5: Generate tokens
  const [access_token, refresh_token] = await Promise.all([
    signAccessToken(atClaims),
    encryptRefreshToken(rtClaims),
  ]);

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in: atClaims.exp - atClaims.iat,
      scope: atClaims.scope,
      refresh_token,
    },
    artifacts: {
      accessTokenClaims: atClaims,
      refreshTokenClaims: rtClaims,
    },
  };
}

/**
 * Issues the `client_credentials` grant.
 */
export async function issueClientCredentialsGrant(
  args: NormalizedClientCredentialsGrantInput,
  options: ClientCredentialsGrantOptions,
): Promise<IssueClientCredentialsGrantReturn> {
  const {
    iss,
    accessTokenOptions,
    signAccessToken = (claims: AccessTokenClaims) =>
      defaultSignAccessToken(claims, {
        ...accessTokenOptions,
        currentDate: options.currentDate,
      }),
    randomJti,
    currentDate,
  } = options;

  const atOpts = accessTokenDefaults(accessTokenOptions);

  // Step 4: Create token payload
  const atClaims = createAccessTokenPayload(
    {
      iss,
      sub: args.client_id,
      aud: args.resource,
      client_id: args.client_id,
      scope: args.scope,
      extraClaims: args.accessTokenExtraClaims,
    },
    {
      randomJti,
      currentDate,
      expiresIn: computeExpiresInSeconds(atOpts.signOptions.expiresIn),
    },
  );

  // Step 5: Generate token
  const access_token = await signAccessToken(atClaims);

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in: atClaims.exp - atClaims.iat,
      scope: atClaims.scope,
      refresh_token: undefined,
    },
    artifacts: {
      accessTokenClaims: atClaims,
    },
  };
}

/**
 * Issues the `refresh_token` grant.
 */
export async function issueRefreshTokenGrant(
  args: NormalizedRefreshTokenGrantInput,
  options: RefreshTokenGrantOptions,
): Promise<IssueRefreshTokenGrantReturn> {
  const {
    iss,
    accessTokenOptions,
    refreshTokenOptions,
    introspectRefreshToken = (token: string) =>
      defaultIntrospectRefreshToken({
        token,
        iss,
        options: refreshTokenOptions,
      }),
    signAccessToken = (claims: AccessTokenClaims) =>
      defaultSignAccessToken(claims, {
        ...accessTokenOptions,
        currentDate: options.currentDate,
      }),
    encryptRefreshToken = (claims: RefreshTokenClaims) =>
      defaultEncryptRefreshToken(claims, {
        ...refreshTokenOptions,
        currentDate: options.currentDate,
      }),
    randomJti,
    currentDate,
  } = options;

  // Step 2: Introspect refresh token if it's a string
  const oldRTClaims =
    typeof args.refresh_token === "string"
      ? await introspectRefreshToken(args.refresh_token)
      : args.refresh_token;

  // Step 3: Validate claims
  const validatedClaims = await validateRefreshTokenClaims(oldRTClaims, args);

  if (!validatedClaims.success) {
    return { success: false, error: validatedClaims.error };
  }

  const validClaims = validatedClaims.value;
  const atOpts = accessTokenDefaults(accessTokenOptions);
  const rtOpts = refreshTokenDefaults(refreshTokenOptions);
  const newScope = args.requested_scope || validClaims.scope;

  // Step 4: Create token payloads (implementing refresh token rotation)
  const atClaims = createAccessTokenPayload(
    {
      iss,
      sub: validClaims.sub,
      aud: validClaims.resource,
      client_id: validClaims.client_id,
      scope: newScope,
      extraClaims: args.accessTokenExtraClaims,
    },
    {
      randomJti,
      currentDate,
      expiresIn: computeExpiresInSeconds(atOpts.signOptions.expiresIn),
    },
  );

  const rtClaims = createRefreshTokenPayload(
    {
      iss,
      sub: validClaims.sub,
      client_id: validClaims.client_id,
      resource: validClaims.resource,
      scope: newScope,
      extraClaims: args.refreshTokenExtraClaims,
    },
    {
      randomJti,
      currentDate,
      expiresIn: computeExpiresInSeconds(rtOpts.encryptOptions.expiresIn),
    },
  );

  // Step 5: Generate tokens
  const [access_token, new_refresh_token] = await Promise.all([
    signAccessToken(atClaims),
    encryptRefreshToken(rtClaims),
  ]);

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in: atClaims.exp - atClaims.iat,
      scope: newScope,
      refresh_token: new_refresh_token,
    },
    artifacts: {
      accessTokenClaims: atClaims,
      refreshTokenClaims: rtClaims,
    },
  };
}

// #endregion grant type handlers
