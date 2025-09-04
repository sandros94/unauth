import { encrypt, decrypt } from "unjwt/jwe";
import { sign, verify } from "unjwt/jws";
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
import {
  isScopeSubset,
  normalizeScope,
  validatePKCE,
  normalizeAudience,
  redactToken,
} from "./utils";
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
      /** Optional audience for JWT access token (RFC 9068). */
      aud?: string | string[];
      /** Optional client identifier if the caller wishes to pass it explicitly. */
      client_id?: string;
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
  cb: (
    opts: ResolvedTokenOptions,
  ) => MaybePromise<JWTClaims & { scope: string }>,
): Promise<OAuthTokenResponse> {
  if (!isOAuthCredentialRequest(args)) {
    throw new Error("[OAuth] Invalid client credentials request");
  }
  if (!cb) {
    throw new Error(
      "[OAuth] Client authentication required for client_credentials",
    );
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
  // Allow the callback to act as client authentication gate and to provide audience
  const extraClaims = await cb(resolved);
  const aud = normalizeAudience(extraClaims.aud ?? args.aud);

  const accessTokenClaims: JWTClaims & { scope: string } = {
    jti: randomJti(),
    ...extraClaims,
    iss: issuer,
    aud,
    scope,
    ...(args.client_id ? { client_id: args.client_id } : {}),
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
    onCodeUsed?: (jti: string) => MaybePromise<void>;
    onAuthenticateClient?: (client_id: string) => MaybePromise<void>;
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
      ...decryptOptions,
    },
  ).catch(() => {
    console.error(
      `[OAuth] Invalid authorization code.\n\tclient=${client_id} code=${redactToken(code)}`,
    );
    throw new Error("[OAuth] Invalid authorization code");
  });

  // Scope comes from the authorization code (preferred) with optional default fallback
  const scope = normalizeScope(payload.scope, defaultScope, availableScopes);

  // Enforce client_id match if present in code
  if (payload.client_id && payload.client_id !== client_id) {
    throw new Error("[OAuth] Invalid client_id for authorization code");
  }

  // Enforce redirect_uri presence and match per OAuth 2.1
  if (payload.redirect_uri) {
    if (!redirect_uri || redirect_uri !== payload.redirect_uri) {
      console.error(
        `[OAuth] redirect_uri mismatch.\n\tclient=${client_id} sent=${redirect_uri} code=${payload.redirect_uri}`,
      );
      throw new Error("[OAuth] Invalid redirect_uri");
    }
  } else if (redirect_uri) {
    console.error(
      `[OAuth] Unexpected redirect_uri in token request without one in code. client=${client_id}`,
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
      `[OAuth] Invalid PKCE. client=${client_id} code=${redactToken(code)}`,
    );
    throw new Error("[OAuth] Invalid PKCE");
  }

  const cbResult = cb
    ? await cb(payload, resolved)
    : {
        accessTokenClaims: {},
        refreshTokenClaims: {},
      };

  if (cbResult.onAuthenticateClient) {
    await cbResult.onAuthenticateClient(client_id);
  }

  const aud = normalizeAudience(cbResult.accessTokenClaims.aud);
  const endUserSub = cbResult.accessTokenClaims.sub || payload.sub;
  if (!endUserSub) {
    throw new Error("[OAuth] Missing subject (sub) for access token");
  }

  const newRefreshTokenClaims = {
    jti: randomJti(),
    ...cbResult.refreshTokenClaims,
    iss: issuer,
    scope,
    sub: cbResult.refreshTokenClaims.sub || endUserSub,
    client_id,
  };

  const newAccessTokenClaims = {
    jti: randomJti(),
    ...cbResult.accessTokenClaims,
    iss: issuer,
    aud,
    scope,
    sub: endUserSub,
    azp: client_id,
    client_id,
  };

  const [access_token, refresh_token] = await Promise.all([
    sign(newAccessTokenClaims, jwsPrivateKey, {
      protectedHeader: { typ: "at+jwt", ...signOptions.protectedHeader },
      ...signOptions,
    }),
    encrypt(newRefreshTokenClaims, jweSecret, {
      protectedHeader: { typ: "at+jwt", ...encryptOptions.protectedHeader },
      ...encryptOptions,
    }),
  ]);

  if (cbResult.onCodeUsed) {
    try {
      await cbResult.onCodeUsed(payload.jti);
    } catch (error_) {
      console.error("[OAuth] onCodeUsed hook failed", error_);
    }
  }

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
    onRefreshUsed?: (jti: string) => MaybePromise<void>;
    onAuthenticateClient?: (client_id: string) => MaybePromise<void>;
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
      ...decryptOptions,
    },
  ).catch(() => {
    console.error(
      `[OAuth] Invalid refresh token. client=${client_id} refresh=${redactToken(oldRefreshToken)}`,
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
      `[OAuth] Invalid scope on refresh. requested=${requestedScope} original=${originalScope}`,
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

  if (cbResult.onAuthenticateClient) {
    await cbResult.onAuthenticateClient(client_id);
  }

  const aud = normalizeAudience(cbResult.accessTokenClaims.aud);
  const endUserSub = cbResult.accessTokenClaims.sub || payload.sub;
  if (!endUserSub) {
    throw new Error("[OAuth] Missing subject (sub) for access token");
  }

  // Enforce client_id match if present in refresh token
  if (payload.client_id && payload.client_id !== client_id) {
    throw new Error("[OAuth] Invalid client_id for refresh token");
  }

  const newRefreshTokenClaims = {
    jti: randomJti(),
    ...cbResult.refreshTokenClaims,
    iss: issuer,
    scope,
    sub: cbResult.refreshTokenClaims.sub || endUserSub,
    client_id,
  };

  const newAccessTokenClaims = {
    jti: randomJti(),
    ...cbResult.accessTokenClaims,
    iss: issuer,
    aud,
    scope,
    sub: endUserSub,
    azp: client_id,
    client_id,
  };

  const [access_token, refresh_token] = await Promise.all([
    sign(newAccessTokenClaims, jwsPrivateKey, {
      protectedHeader: { typ: "at+jwt", ...signOptions.protectedHeader },
      ...signOptions,
    }),
    encrypt(newRefreshTokenClaims, jweSecret, {
      protectedHeader: { typ: "at+jwt", ...encryptOptions.protectedHeader },
      ...encryptOptions,
    }),
  ]);

  if (cbResult.onRefreshUsed) {
    try {
      await cbResult.onRefreshUsed(payload.jti);
    } catch (error_) {
      console.error("[OAuth] onRefreshUsed hook failed", error_);
    }
  }

  return {
    access_token,
    token_type: DEFAULTS.tokenType,
    expires_in: signOptions?.expiresIn,
    scope,
    refresh_token,
  };
}

/** Map JWT claims to an RFC 7662 introspection response shape */
export function mapIntrospectionResponse(
  claims: JWTClaims,
  extras?: Partial<{ token_type: string }>,
): JWTClaims & {
  active: boolean;
  token_type: string;
} {
  const { iss, sub, aud, exp, nbf, iat, jti, scope, client_id, ...rest } =
    claims;
  const out: JWTClaims & {
    active: boolean;
    token_type: string;
  } = {
    active: true,
    iss,
    sub,
    aud,
    exp,
    nbf,
    iat,
    jti,
    scope,
    client_id,
    token_type: extras?.token_type || DEFAULTS.tokenType,
  };
  for (const [k, v] of Object.entries(rest)) {
    if (v === undefined) continue;
    out[k] = v;
  }
  return out;
}

/**
 * Minimal token revocation helper: decrypts/verifies token to obtain its jti, then invokes onRevoke hook.
 */
export async function revokeToken(
  token: string,
  kind: "access" | "refresh" | "code",
  options: OAuthTokenOptions,
  cb: {
    onRevoke: (claims: {
      jti: string;
      iat: number;
      exp: number;
    }) => MaybePromise<void>;
  },
): Promise<void> {
  const { jweSecret, jwsPrivateKey, decryptOptions, verifyOptions, issuer } =
    options;
  try {
    if (kind === "access") {
      const { payload } = await verify<{
        jti: string;
        iat: number;
        exp: number;
      }>(token, jwsPrivateKey, {
        issuer,
        typ: "at+jwt",
        ...verifyOptions,
      });
      await cb.onRevoke({
        jti: payload.jti,
        iat: payload.iat,
        exp: payload.exp,
      });
    } else {
      const { payload } = await decrypt<{
        jti: string;
        iat: number;
        exp: number;
      }>(token, jweSecret, {
        issuer,
        typ: "at+jwt",
        ...decryptOptions,
      });
      await cb.onRevoke({
        jti: payload.jti,
        iat: payload.iat,
        exp: payload.exp,
      });
    }
  } catch {
    // Spec: revocation should be idempotent; no token details should be logged
    return;
  }
}
