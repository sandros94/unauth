import { computeExpiresInSeconds } from "unjwt/utils";
import { encrypt } from "unjwt/jwe";
import { sign } from "unjwt/jws";

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
  introspectAuthorizationCode,
  introspectRefreshToken,
} from "./introspect";
import { isScopeSubset, validatePKCE } from "./utils";

// #region types

export type TokenGrantType =
  | "authorization_code"
  | "refresh_token"
  | "client_credentials";

export interface NormalizedAuthorizationCodeGrantInput {
  type: "authorization_code";
  client_id: string;
  code: string | AuthorizationCodeClaims;
  code_verifier: string;
  accessTokenExtraClaims?: Record<string, unknown>;
  refreshTokenExtraClaims?: Record<string, unknown>;
}

export interface NormalizedClientCredentialsGrantInput {
  type: "client_credentials";
  client_id: string;
  resource: string | string[];
  scope?: string;
  accessTokenExtraClaims?: Record<string, unknown>;
}

export interface NormalizedRefreshTokenGrantInput {
  type: "refresh_token";
  client_id: string;
  refresh_token: string | RefreshTokenClaims;
  requested_scope?: string;
  accessTokenExtraClaims?: Record<string, unknown>;
  refreshTokenExtraClaims?: Record<string, unknown>;
}

export type NormalizedTokenInput =
  | NormalizedAuthorizationCodeGrantInput
  | NormalizedRefreshTokenGrantInput
  | NormalizedClientCredentialsGrantInput;

export interface IssueTokenGrantOptions {
  iss: string;
  authorizationCodeOptions: AuthorizationCodeOptions;
  accessTokenOptions: AccessTokenOptions;
  refreshTokenOptions: RefreshTokenOptions;
  /**
   * A function to generate a unique identifier for tokens.
   */
  randomJti?: () => string;
  /**
   * Date to use when computing NumericDate claims, defaults to `new Date()`.
   */
  currentDate?: Date;
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

export type IssueTokenGrantReturn =
  | IssueAuthorizationCodeGrantReturn
  | IssueClientCredentialsGrantReturn
  | IssueRefreshTokenGrantReturn;

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

async function validateAuthorizationCodeClaims(
  claims: AuthorizationCodeClaims,
  input: NormalizedAuthorizationCodeGrantInput,
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Promise<
  Result<NormalizedAuthorizationCodeGrantInput, undefined, TokenErrorResponse>
> {
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

  // TODO: Per RFC 8707, resource maps to aud, but RFC 9068 is both required but also accept a fallback registered for the client?
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

  return pkceIsValid
    ? { success: true, value: input }
    : {
        success: false,
        error: tokenError(
          "invalid_grant",
          "Invalid PKCE code_verifier",
          errorDetails,
        ),
      };
}

async function validateRefreshTokenClaims(
  claims: RefreshTokenClaims,
  input: NormalizedRefreshTokenGrantInput,
  errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
): Promise<
  Result<NormalizedRefreshTokenGrantInput, undefined, TokenErrorResponse>
> {
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

  // Validate new requested scope
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

  // TODO: Per RFC 8707, resource maps to aud, but RFC 9068 is both required but also accept a fallback registered for the client?
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

  return { success: true, value: input };
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

  // requested_scope is optional and can be undefined
  // but if present it must be a subset of the original scope
  // which will be validated later during processing

  return {
    success: true,
    value: input,
  };
}

// #endregion internals

// #region validations

export function validateTokenGrantType(
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
    return validateAuthorizationCodeGrantRequest({
      type: "authorization_code",
      client_id: req.client_id,
      code: req.code,
      code_verifier: req.code_verifier,
      accessTokenExtraClaims: req.accessTokenExtraClaims,
      refreshTokenExtraClaims: req.refreshTokenExtraClaims,
    });
  }

  if (isClientCredentialsGrantRequest(req)) {
    return validateClientCredentialsGrantRequest({
      type: "client_credentials",
      client_id: req.client_id,
      resource: req.resource,
      scope: req.scope,
      accessTokenExtraClaims: req.accessTokenExtraClaims,
    });
  }

  if (isRefreshTokenGrantRequest(req)) {
    return validateRefreshTokenGrantRequest({
      type: "refresh_token",
      client_id: req.client_id,
      refresh_token: req.refresh_token,
      requested_scope: req.scope,
      accessTokenExtraClaims: req.accessTokenExtraClaims,
      refreshTokenExtraClaims: req.refreshTokenExtraClaims,
    });
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

// #endregion validations

// #region runtime

/**
 * Issues the `authorization_code` grant.
 */
export async function issueAuthorizationCodeGrant(
  args: NormalizedAuthorizationCodeGrantInput,
  options: IssueTokenGrantOptions,
): Promise<IssueAuthorizationCodeGrantReturn> {
  const {
    iss,
    authorizationCodeOptions,
    accessTokenOptions,
    refreshTokenOptions,
  } = options;

  const codeClaims =
    typeof args.code === "string"
      ? await introspectAuthorizationCode({
          token: args.code,
          iss,
          options: authorizationCodeOptions,
        })
      : args.code;

  const validatedClaims = await validateAuthorizationCodeClaims(
    codeClaims,
    args,
  );

  if (!validatedClaims.success) {
    return { success: false, error: validatedClaims.error };
  }
  const { accessTokenExtraClaims, refreshTokenExtraClaims } =
    validatedClaims.value;

  const atOpts = accessTokenDefaults(accessTokenOptions);
  const rtOpts = refreshTokenDefaults(refreshTokenOptions);

  const randomJti = options.randomJti || crypto.randomUUID;
  const currentDate =
    (options.currentDate ||
      atOpts.signOptions.currentDate ||
      rtOpts.encryptOptions.currentDate) ??
    new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);
  const expiresIn = computeExpiresInSeconds(atOpts.signOptions.expiresIn);

  const atClaims: AccessTokenClaims = {
    ...accessTokenExtraClaims,
    jti: randomJti(),
    iss,
    sub: codeClaims.sub,
    aud: codeClaims.resource,
    exp: iat + expiresIn,
    iat,
    client_id: codeClaims.client_id,
    scope: codeClaims.scope,
  };

  const rtClaims: RefreshTokenClaims = {
    ...refreshTokenExtraClaims,
    jti: randomJti(),
    iss,
    sub: codeClaims.sub,
    exp: iat + computeExpiresInSeconds(rtOpts.encryptOptions.expiresIn),
    iat,
    client_id: codeClaims.client_id,
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
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in: expiresIn,
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
  options: IssueTokenGrantOptions,
): Promise<IssueClientCredentialsGrantReturn> {
  const { client_id, resource, scope, accessTokenExtraClaims } = args;
  const { iss, accessTokenOptions } = options;

  const atOpts = accessTokenDefaults(accessTokenOptions);

  const randomJti = options.randomJti || crypto.randomUUID;
  const currentDate =
    (options.currentDate || atOpts.signOptions.currentDate) ?? new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);
  const expiresIn = computeExpiresInSeconds(atOpts.signOptions.expiresIn);

  const atClaims: AccessTokenClaims = {
    ...accessTokenExtraClaims,
    jti: randomJti(),
    iss,
    sub: client_id,
    aud: resource,
    exp: iat + expiresIn,
    iat,
    client_id: client_id,
    scope: scope,
  };

  const access_token = await sign(atClaims, atOpts.privateKey, {
    ...atOpts.signOptions,
    protectedHeader: { ...atOpts.signOptions.protectedHeader, typ: "at+jwt" },
    currentDate,
  });

  return {
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in: expiresIn,
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
  options: IssueTokenGrantOptions,
): Promise<IssueRefreshTokenGrantReturn> {
  const { iss, accessTokenOptions, refreshTokenOptions } = options;

  const refreshTokenClaims =
    typeof args.refresh_token === "string"
      ? await introspectRefreshToken({
          token: args.refresh_token,
          iss,
          options: refreshTokenOptions,
        })
      : args.refresh_token;

  const validatedClaims = await validateRefreshTokenClaims(
    refreshTokenClaims,
    args,
  );

  if (!validatedClaims.success) {
    return { success: false, error: validatedClaims.error };
  }
  const { requested_scope, accessTokenExtraClaims, refreshTokenExtraClaims } =
    validatedClaims.value;

  const atOpts = accessTokenDefaults(accessTokenOptions);
  const rtOpts = refreshTokenDefaults(refreshTokenOptions);

  // 5. Build new tokens (implementing refresh token rotation)
  const randomJti = options.randomJti || crypto.randomUUID;
  const currentDate =
    (options.currentDate ||
      atOpts.signOptions.currentDate ||
      rtOpts.encryptOptions.currentDate) ??
    new Date();
  const iat = Math.floor(currentDate.getTime() / 1000);
  const expiresIn = computeExpiresInSeconds(atOpts.signOptions.expiresIn);
  const newScope = requested_scope || refreshTokenClaims.scope;

  const newAccessTokenClaims: AccessTokenClaims = {
    ...accessTokenExtraClaims,
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
    ...refreshTokenExtraClaims,
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
    success: true,
    value: {
      access_token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope: newScope,
      refresh_token: new_refresh_token,
    },
    artifacts: {
      accessTokenClaims: newAccessTokenClaims,
      refreshTokenClaims: newRefreshTokenClaims,
    },
  };
}

// #endregion runtime
