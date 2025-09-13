import { encrypt } from "unjwt/jwe";
import { sign } from "unjwt/jws";
import type { JWK } from "unjwt";

import type { AccessTokenClaims, RefreshTokenClaims } from "../types";
import type { ResolvedOAuthOptions } from "./defaults";
import { type TokenErrorResponse, OAuthError } from "./error";
import { validatePKCE, isScopeSubset } from "./utils";
import {
  introspectAuthorizationCode,
  introspectRefreshToken,
} from "./introspect";

/**
 * Represents a token request from a client to the token endpoint.
 * This is a discriminated union based on the `grant_type`.
 */
export type TokenRequest =
  | AuthorizationCodeTokenRequest
  | RefreshTokenRequest
  | ClientCredentialsTokenRequest;

export interface AuthorizationCodeTokenRequest {
  grant_type: "authorization_code";
  /** The authorization code received from the authorization server. */
  code: string;
  /** The client identifier. REQUIRED for public clients. */
  client_id: string;
  /**
   * The PKCE code verifier. REQUIRED if `code_challenge` was used in the
   * authorization request, which is mandatory in OAuth 2.1.
   */
  code_verifier: string;
}

export interface RefreshTokenRequest {
  grant_type: "refresh_token";
  /** The refresh token issued to the client. */
  refresh_token: string;
  /**
   * The scope of the access request. MUST NOT include any scope not
   * originally granted. If omitted, the original scope is used.
   */
  scope?: string;
  /** The client identifier, used for binding validation. */
  client_id?: string;
}

export interface ClientCredentialsTokenRequest {
  grant_type: "client_credentials";
  /** The requested scope, limited to the client's own permissions. */
  scope?: string;
}

/**
 * Represents a successful response from the token endpoint.
 */
export interface TokenResponse {
  /** The access token. */
  access_token: string;
  /** The type of token (case-insensitive). MUST be "Bearer" for this implementation. */
  token_type: "Bearer";
  /** The lifetime in seconds of the access token. */
  expires_in: number;
  /** The scope of the access token issued. */
  scope?: string;
  /** A new refresh token (optional, e.g., for rotation). */
  refresh_token?: string;
}

interface IssueTokenKeys {
  authorizationCode: string | JWK;
  accessToken: JWK;
  refreshToken: string | JWK;
}

// --- Internal Grant-Specific Handlers ---

/**
 * Handles the `authorization_code` grant flow.
 */
export async function handleAuthorizationCodeGrant(
  req: AuthorizationCodeTokenRequest,
  opts: ResolvedOAuthOptions,
  keys?: IssueTokenKeys,
): Promise<TokenResponse> {
  const { accessToken, refreshToken, issuer, randomJti } = opts;

  // 1. Decrypt the authorization code
  const { payload: codeClaims } = await introspectAuthorizationCode(
    req.code,
    keys?.authorizationCode || opts.authorizationCode.privateKey,
    opts,
  ).catch(() => {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Invalid authorization code",
    });
  });

  // 2. Validate claims from the code against the request
  if (codeClaims.client_id !== req.client_id) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Authorization code was issued to a different client",
    });
  }

  // 3. Validate resource/audience or fallback to defaultAudience
  // Per RFC 8707, resource maps to aud, and per RFC 9068 is both required and falls back to defaultAudience then scope
  const aud = codeClaims.resource || opts.defaultAudience || codeClaims.scope;
  if (!aud) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Missing resource, scope, and default audience",
    });
  }

  // 4. Verify PKCE
  if (!codeClaims.code_challenge || !codeClaims.code_challenge_method) {
    throw new OAuthError({
      error: "invalid_request",
      error_description: "Missing code_challenge in authorization session",
    });
  }

  const pkceIsValid = await validatePKCE(
    req.code_verifier,
    codeClaims.code_challenge,
    codeClaims.code_challenge_method,
  );

  if (!pkceIsValid) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Invalid PKCE code_verifier",
    });
  }

  // Hook to also validate the claims externally before issuing tokens
  await opts.hooks?.onAuthorizationCodeCheck?.({ claims: codeClaims });

  // 5. Build tokens
  const scope = codeClaims.scope || opts.defaultScope;
  const iat = Math.floor(opts.currentDate.getTime() / 1000);

  const accessTokenClaims: AccessTokenClaims = {
    jti: randomJti(),
    iss: issuer,
    sub: codeClaims.sub,
    aud,
    exp: iat + accessToken.signOptions.expiresIn,
    iat,
    client_id: req.client_id,
    scope,
  };

  const refreshTokenClaims: RefreshTokenClaims = {
    jti: randomJti(),
    iss: issuer,
    sub: codeClaims.sub,
    exp: iat + refreshToken.encryptOptions.expiresIn,
    iat,
    client_id: req.client_id,
    resource: codeClaims.resource,
    scope,
  };

  const [access_token, refresh_token] = await Promise.all([
    sign(
      accessTokenClaims,
      keys?.accessToken || accessToken.privateKey,
      accessToken.signOptions,
    ),
    encrypt(
      refreshTokenClaims,
      keys?.refreshToken || refreshToken.privateKey,
      refreshToken.encryptOptions,
    ),
  ]);

  // OAuth 2.1 requires single-use authorization codes. Revocation logic should be handled externally.
  await opts.hooks?.onAuthorizationCodeUsed?.(
    { claims: codeClaims },
    { atClaims: accessTokenClaims, rtClaims: refreshTokenClaims },
  );

  return {
    access_token,
    token_type: "Bearer",
    expires_in: accessToken.signOptions.expiresIn,
    scope,
    refresh_token,
  };
}

/**
 * Handles the `refresh_token` grant flow.
 */
export async function handleRefreshTokenGrant(
  req: RefreshTokenRequest,
  opts: ResolvedOAuthOptions,
  keys?: IssueTokenKeys,
): Promise<TokenResponse> {
  const { accessToken, refreshToken, issuer, randomJti } = opts;

  // 1. Decrypt the refresh token
  const { payload: oldTokenClaims } = await introspectRefreshToken(
    req.refresh_token,
    keys?.refreshToken || refreshToken.privateKey,
    opts,
  ).catch(() => {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Invalid refresh token",
    });
  });

  // 2. Validate client binding
  if (req.client_id && oldTokenClaims.client_id !== req.client_id) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Refresh token was issued to a different client",
    });
  }

  // 3. Validate scope
  const originalScope = oldTokenClaims.scope;
  const requestedScope = req.scope;
  if (
    requestedScope &&
    originalScope &&
    !isScopeSubset(requestedScope, originalScope)
  ) {
    throw new OAuthError({
      error: "invalid_scope",
      error_description: "Requested scope exceeds original grant",
    });
  }
  const newScope = requestedScope ?? originalScope;

  // 4. Validate resource/audience or fallback to defaultAudience
  // Per RFC 8707, resource maps to aud, and per RFC 9068 is both required and falls back to defaultAudience then scope
  const aud = oldTokenClaims.resource || opts.defaultAudience || newScope;
  if (!aud) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Missing resource, scope, and default audience",
    });
  }

  // Hook to also validate the claims externally before issuing tokens
  await opts.hooks?.onRefreshTokenCheck?.({ claims: oldTokenClaims });

  // 5. Build new tokens (implementing refresh token rotation)
  const iat = Math.floor(opts.currentDate.getTime() / 1000);

  const newAccessTokenClaims: AccessTokenClaims = {
    jti: randomJti(),
    iss: issuer,
    sub: oldTokenClaims.sub,
    aud,
    exp: iat + accessToken.signOptions.expiresIn,
    iat,
    client_id: oldTokenClaims.client_id,
    scope: newScope,
  };

  const newRefreshTokenClaims: RefreshTokenClaims = {
    jti: randomJti(),
    iss: issuer,
    sub: oldTokenClaims.sub,
    exp: iat + refreshToken.encryptOptions.expiresIn,
    iat,
    client_id: oldTokenClaims.client_id,
    resource: oldTokenClaims.resource,
    scope: newScope, // The new refresh token carries the potentially narrowed scope
  };

  const [access_token, new_refresh_token] = await Promise.all([
    sign(
      newAccessTokenClaims,
      keys?.accessToken || accessToken.privateKey,
      accessToken.signOptions,
    ),
    encrypt(
      newRefreshTokenClaims,
      keys?.refreshToken || refreshToken.privateKey,
      refreshToken.encryptOptions,
    ),
  ]);

  // OAuth 2.1 suggests single-use refresh token. Revocation logic should be handled externally.
  await opts.hooks?.onRefreshTokenUsed?.(
    { claims: oldTokenClaims },
    { atClaims: newAccessTokenClaims, rtClaims: newRefreshTokenClaims },
  );

  return {
    access_token,
    token_type: "Bearer",
    expires_in: accessToken.signOptions.expiresIn,
    scope: newScope,
    refresh_token: new_refresh_token,
  };
}

/**
 * Handles the `client_credentials` grant flow.
 */
export async function handleClientCredentialsGrant(
  req: ClientCredentialsTokenRequest,
  opts: ResolvedOAuthOptions,
  keys?: IssueTokenKeys,
): Promise<TokenResponse> {
  // This grant MUST only be used by confidential clients.
  if (!opts.hooks?.onClientAuthenticate) {
    throw new OAuthError({
      error: "server_error",
      error_description: "Client authentication handler not implemented",
    });
  }

  const clientClaims = await opts.hooks.onClientAuthenticate({
    scope: req.scope,
  });

  if (!clientClaims || !clientClaims.sub || !clientClaims.client_id) {
    throw new OAuthError({
      error: "invalid_client",
      error_description: "Client authentication failed",
    });
  }

  const scope = clientClaims.scope || opts.defaultScope;

  // Validate resource/audience or fallback to defaultAudience
  // Per RFC 8707, resource maps to aud, and per RFC 9068 is both required and falls back to defaultAudience then scope
  const aud =
    clientClaims.aud || clientClaims.resource || opts.defaultAudience || scope;
  if (!aud) {
    throw new OAuthError({
      error: "invalid_grant",
      error_description: "Missing resource, scope, and default audience",
    });
  }

  const { accessToken, issuer, randomJti } = opts;
  const iat = Math.floor(opts.currentDate.getTime() / 1000);
  const accessTokenClaims: AccessTokenClaims = {
    jti: randomJti(),
    ...clientClaims,
    sub: clientClaims.sub || clientClaims.client_id,
    iss: issuer,
    iat,
    exp: iat + accessToken.signOptions.expiresIn,
    aud,
    scope,
  };

  const access_token = await sign(
    accessTokenClaims,
    keys?.accessToken || accessToken.privateKey,
    accessToken.signOptions,
  );

  await opts.hooks?.onClientAuthenticated?.({ claims: accessTokenClaims });

  return {
    access_token,
    token_type: "Bearer",
    expires_in: accessToken.signOptions.expiresIn,
    scope,
  };
}

// --- Main Public API ---

export async function issueAccessToken(
  options: ResolvedOAuthOptions,
  keys?: IssueTokenKeys,
): Promise<TokenResponse | TokenErrorResponse> {
  try {
    if (!options.hooks?.onTokenRequest) {
      throw new OAuthError({
        error: "server_error",
        error_description: "Token request handler not implemented",
        iss: options.issuer,
      });
    }

    let request: TokenRequest;
    try {
      request = await options.hooks.onTokenRequest();
    } catch (error) {
      if (error instanceof OAuthError) {
        throw error;
      }
      throw new OAuthError({
        error: "invalid_request",
        error_description: "Failed to parse token request",
        iss: options.issuer,
      });
    }

    switch (request.grant_type) {
      case "authorization_code": {
        return await handleAuthorizationCodeGrant(request, options, keys);
      }

      case "refresh_token": {
        return await handleRefreshTokenGrant(request, options, keys);
      }

      case "client_credentials": {
        return await handleClientCredentialsGrant(request, options, keys);
      }

      default: {
        throw new OAuthError({
          error: "unsupported_grant_type",
          // @ts-expect-error - request has an invalid grant_type
          error_description: `Unsupported grant_type: ${request.grant_type}`,
        });
      }
    }
  } catch (error) {
    if (error instanceof OAuthError) {
      return new OAuthError({
        ...error.toJSON(),
        iss: error.iss || options.issuer,
      }).toJSON();
    }
    // Convert generic errors to OAuth errors
    console.error("Unhandled error during token issuance:", error);
    return new OAuthError({
      error: "server_error",
      iss: options.issuer,
    }).toJSON();
  }
}
