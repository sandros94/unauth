import { encrypt, decrypt } from "unjwt/jwe";
import { sign } from "unjwt/jws";
import type {
  JWK,
  JWTClaims,
  JWEDecryptOptions,
  JWSSignOptions,
  JWSVerifyOptions,
} from "unjwt";

import type { OAuthAuthorizeOptions } from "./authorize";
import type { MaybePromise } from "../types/index";
import type {
  OAuthRefreshTokenClaims,
  OAuthAuthorizationCodeClaims,
} from "./types";
import { isScopeSubset, normalizeScope, validatePKCE } from "./utils";
import {
  type ResolvedTokenOptions,
  DEFAULTS,
  withTokenDefaults,
} from "./defaults";

/**
 * OAuth 2.1 Token Endpoint utilities
 * These helpers validate the token request, issue access tokens, and handle token revocation.
 */

export type OAuthTokenRequest =
  | {
      /**
       * The grant type for a token refresh request.
       */
      grant_type: "refresh_token";
      /**
       * The refresh token issued by the authorization server.
       */
      refresh_token: string;
      /**
       * The client identifier for both public and confidential clients. The `refresh_token` will
       * be validated against the `client_id` registered with the authorization server.
       */
      client_id: string;
      /**
       * The scope of the access request.
       */
      scope?: string;
    }
  | {
      /**
       * The authorization server MUST authenticate the client.
       */
      grant_type: "client_credentials";
      /**
       * The scope of the access request.
       */
      scope?: string;
    }
  | {
      /**
       * The authorization code grant type is used by clients to exchange an authorization code for an access token.
       */
      grant_type: "authorization_code";
      /**
       * The authorization code received from the authorization server.
       */
      code: string;
      /**
       * The client identifier for both public and confidential clients. The `code` will
       * be validated against the `client_id` registered with the authorization server.
       */
      client_id: string;
      /**
       * The original code verifier string. Must be validated only if the `code_challenge`
       * parameter was included in the authorization request. MUST NOT be used otherwise.
       */
      code_verifier?: string;
      /**
       * Available for backward compatibility with OAuth 2.0
       *
       * @deprecated use `code_challenge` instead.
       */
      redirect_uri?: string;
    };

export interface OAuthTokenResponse {
  /**
   * The access token issued by the authorization server.
   */
  access_token: string;
  /**
   * The type of the access token issued. Value is case insensitive.
   */
  token_type: "Bearer";
  /**
   * The lifetime in seconds of the access token.
   * @default 3600
   */
  expires_in: number;
  /**
   * If identical to the scope requested by the client; otherwise, REQUIRED.
   */
  scope: string;
  /**
   * The refresh token, which can be used to obtain new access tokens
   * based on the grant passed in the corresponding token request.
   */
  refresh_token?: string;
}

export interface OAuthTokenOptions extends OAuthAuthorizeOptions {
  /**
   * The private key used to sign the access token.
   */
  jwsPrivateKey: JWK;
  /**
   * Options for decrypting the refresh token.
   */
  decryptOptions?: JWEDecryptOptions;
  /**
   * Options for signing the access token.
   */
  signOptions?: JWSSignOptions;
  /**
   * Options for verifying the access token.
   */
  verifyOptions?: JWSVerifyOptions;
}

export function isOAuthCredentialRequest(
  request: unknown,
): request is Extract<OAuthTokenRequest, { grant_type: "client_credentials" }> {
  return (
    typeof request === "object" &&
    request !== null &&
    "grant_type" in request &&
    request.grant_type === "client_credentials"
  );
}

export function isOAuthRefreshTokenRequest(
  request: unknown,
): request is Extract<OAuthTokenRequest, { grant_type: "refresh_token" }> {
  return (
    typeof request === "object" &&
    request !== null &&
    "grant_type" in request &&
    request.grant_type === "refresh_token"
  );
}

export function isOAuthAuthorizationCodeRequest(
  request: unknown,
): request is Extract<OAuthTokenRequest, { grant_type: "authorization_code" }> {
  return (
    typeof request === "object" &&
    request !== null &&
    "grant_type" in request &&
    request.grant_type === "authorization_code"
  );
}

export async function oAuthClientCredentials(
  args: Extract<OAuthTokenRequest, { grant_type: "client_credentials" }>,
  options: OAuthTokenOptions,
  cb?: (
    opts: ResolvedTokenOptions,
  ) => MaybePromise<JWTClaims & { scope: string }>,
): Promise<OAuthTokenResponse> {
  if (!isOAuthCredentialRequest(args)) {
    throw new Error("[OAuth] Invalid client credentials request");
  }

  const resolved = withTokenDefaults(options);
  const {
    issuer,
    jwsPrivateKey,
    randomJti,
    signOptions,
    defaultScope,
    availableScopes,
  } = resolved;
  const scope = normalizeScope(args.scope, defaultScope, availableScopes);
  const extraClaims = cb ? await cb(resolved) : {};

  const accessTokenClaims: JWTClaims & { scope: string } = {
    jti: randomJti(),
    ...extraClaims,
    iss: issuer,
    scope,
  };

  const access_token = await sign(
    accessTokenClaims,
    jwsPrivateKey,
    signOptions,
  );

  return {
    access_token,
    token_type: DEFAULTS.tokenType,
    expires_in: signOptions?.expiresIn,
    scope,
  };
}

export async function oAuthAuthorizationCode(
  args: Extract<OAuthTokenRequest, { grant_type: "authorization_code" }>,
  options: OAuthTokenOptions,
  cb?: (
    claims: OAuthAuthorizationCodeClaims,
    opts: ResolvedTokenOptions,
  ) => MaybePromise<{
    accessTokenClaims: JWTClaims & { scope?: string };
    refreshTokenClaims: JWTClaims & { scope?: string };
  }>,
): Promise<OAuthTokenResponse> {
  if (!isOAuthAuthorizationCodeRequest(args)) {
    throw new Error("[OAuth] Invalid authorization code request");
  }

  const { client_id, code, code_verifier, redirect_uri } = args;
  const resolved = withTokenDefaults(options);
  const {
    issuer,
    jweSecret,
    jwsPrivateKey,
    randomJti,
    decryptOptions,
    encryptOptions,
    signOptions,
    defaultScope,
    availableScopes,
  } = resolved;

  const { payload } = await decrypt<OAuthAuthorizationCodeClaims>(
    code,
    jweSecret,
    {
      issuer,
      subject: client_id,
      ...decryptOptions,
    },
  ).catch(() => {
    console.error(
      `[OAuth] Invalid authorization code.\n\t${client_id} tried to exchange code with: ${code}`,
    );
    throw new Error("[OAuth] Invalid authorization code");
  });

  // Scope comes from the authorization code (preferred) with optional default fallback
  const scope = normalizeScope(payload.scope, defaultScope, availableScopes);

  // Optional: if redirect_uri was present in both the token request and the code, enforce equality
  if (
    redirect_uri &&
    payload.redirect_uri &&
    redirect_uri !== payload.redirect_uri
  ) {
    console.error(
      `[OAuth] redirect_uri mismatch.\n\t${client_id} sent ${redirect_uri}, code has ${payload.redirect_uri}`,
    );
    throw new Error("[OAuth] Invalid redirect_uri");
  }

  if (
    !code_verifier ||
    !payload.code_challenge ||
    !(await validatePKCE(
      code_verifier,
      payload.code_challenge,
      payload.code_challenge_method,
    ))
  ) {
    console.error(
      `[OAuth] Invalid PKCE.\n\t${client_id} tried to exchange code with: ${code}`,
    );
    throw new Error("[OAuth] Invalid PKCE");
  }

  const cbResult = cb
    ? await cb(payload, resolved)
    : {
        accessTokenClaims: {},
        refreshTokenClaims: {},
      };

  const newRefreshTokenClaims = {
    jti: randomJti(),
    ...cbResult.refreshTokenClaims,
    iss: issuer,
    scope,
    sub: client_id,
  };

  const newAccessTokenClaims = {
    jti: randomJti(),
    ...cbResult.accessTokenClaims,
    iss: issuer,
    scope,
    sub: client_id,
  };

  const [access_token, refresh_token] = await Promise.all([
    sign(newAccessTokenClaims, jwsPrivateKey, signOptions),
    encrypt(newRefreshTokenClaims, jweSecret, encryptOptions),
  ]);

  return {
    access_token,
    token_type: DEFAULTS.tokenType,
    expires_in: signOptions?.expiresIn,
    scope,
    refresh_token,
  };
}

export async function oAuthRefreshToken(
  args: Extract<OAuthTokenRequest, { grant_type: "refresh_token" }>,
  options: OAuthTokenOptions,
  cb?: (
    claims: OAuthRefreshTokenClaims,
    opts: ResolvedTokenOptions,
  ) => MaybePromise<{
    accessTokenClaims: JWTClaims & { scope?: string };
    refreshTokenClaims: JWTClaims & { scope?: string };
  }>,
): Promise<OAuthTokenResponse> {
  if (!isOAuthRefreshTokenRequest(args)) {
    throw new Error("[OAuth] Invalid refresh token request");
  }

  const { refresh_token: oldRefreshToken, client_id } = args;
  const resolved = withTokenDefaults(options);
  const {
    issuer,
    jweSecret,
    jwsPrivateKey,
    randomJti,
    decryptOptions,
    encryptOptions,
    signOptions,
    defaultScope,
    availableScopes,
  } = resolved;

  const { payload } = await decrypt<OAuthRefreshTokenClaims>(
    oldRefreshToken,
    jweSecret,
    {
      issuer,
      subject: client_id,
      ...decryptOptions,
    },
  ).catch(() => {
    console.error(
      `[OAuth] Invalid refresh token.\n\t${client_id} tried to refresh token with: ${oldRefreshToken}`,
    );
    throw new Error("[OAuth] Invalid refresh token");
  });

  // Scope rules (OAuth 2.1): if scope is omitted, reuse original; if present, MUST be a subset of originally granted scope
  const originalScope = normalizeScope(
    payload.scope,
    defaultScope,
    availableScopes,
  );
  const requestedScope = normalizeScope(
    args.scope || originalScope,
    originalScope,
    availableScopes,
  );
  if (args.scope && !isScopeSubset(requestedScope, originalScope)) {
    console.error(
      `[OAuth] Invalid scope on refresh.\n\trequested: ${requestedScope}\n\toriginal: ${originalScope}`,
    );
    throw new Error("[OAuth] Invalid scope");
  }
  const scope = requestedScope;

  const cbResult = cb
    ? await cb(payload, resolved)
    : {
        accessTokenClaims: {},
        refreshTokenClaims: {},
      };

  const newRefreshTokenClaims = {
    jti: randomJti(),
    ...cbResult.refreshTokenClaims,
    iss: issuer,
    scope,
    sub: client_id,
  };

  const newAccessTokenClaims = {
    jti: randomJti(),
    ...cbResult.accessTokenClaims,
    iss: issuer,
    scope,
    sub: client_id,
  };

  const [access_token, refresh_token] = await Promise.all([
    sign(newAccessTokenClaims, jwsPrivateKey, signOptions),
    encrypt(newRefreshTokenClaims, jweSecret, encryptOptions),
  ]);

  return {
    access_token,
    token_type: DEFAULTS.tokenType,
    expires_in: signOptions?.expiresIn,
    scope,
    refresh_token,
  };
}
