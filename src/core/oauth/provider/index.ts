export * from "./error";
export * from "./internal";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import type { MaybePromise } from "../../../types";
import { deepFreeze } from "../../../utils";

import type {
  Result,
  AuthorizeRequest,
  AuthorizeErrorResponse,
  AuthorizationCodeClaims,
  TokenRequest,
  TokenErrorResponse,
  AccessTokenClaims,
  RefreshTokenClaims,
} from "../types";
import type {
  OAuthProviderOptions,
  OAuthDiscoveryDocument,
  ResolvedAuthorizationCodeOptions,
  ResolvedAccessTokenOptions,
  ResolvedRefreshTokenOptions,
  NormalizedAuthorizeInput,
  IssueAuthorizationCodeReturn,
  NormalizedTokenInput,
  IssueTokenGrantReturn,
} from "./internal";
import {
  oauthProviderDefaults,
  introspectAuthorizationCode,
  introspectAccessToken,
  introspectRefreshToken,
  validateRedirectUri,
  validateAuthorizeRequest,
  issueAuthorizationCode,
  validateTokenRequest,
  issueTokenGrant,
} from "./internal";

/**
 * OAuthProvider
 *
 * A thin convenience wrapper over the low-level helpers exported from this module.
 * It shares a common issuer and token options across authorize, token, and
 * introspection helpers. All standalone helpers remain exported above; this class
 * is purely ergonomic and does not add new logic.
 */
export class OAuthProvider {
  private _ac: ResolvedAuthorizationCodeOptions;
  private _rt: ResolvedRefreshTokenOptions;
  private _at: ResolvedAccessTokenOptions;
  private _randomJti: () => string;
  private _discovery: OAuthDiscoveryDocument;
  private _jwkSet: JWKSet;

  constructor(opts: OAuthProviderOptions) {
    const r = oauthProviderDefaults(opts);
    this._discovery = r.discovery;
    this._jwkSet = getPublicKeys(r.accessTokenOptions.publicKey);
    this._ac = r.authorizationCodeOptions;
    this._rt = r.refreshTokenOptions;
    this._at = r.accessTokenOptions;
    this._randomJti = r.randomJti;
  }

  get issuer() {
    return this._discovery.issuer;
  }
  get discoveryDocument() {
    return deepFreeze(this._discovery);
  }
  get jwkSet() {
    return {
      keys: [...this._jwkSet.keys],
    };
  }
  get authorizationCodeOptions() {
    return deepFreeze(this._ac);
  }
  get refreshTokenOptions() {
    return deepFreeze(this._rt);
  }
  get accessTokenOptions() {
    return deepFreeze(this._at);
  }
  get randomJti() {
    return this._randomJti;
  }
  get options() {
    return Object.freeze({
      iss: this.issuer,
      authorizationCodeOptions: this.authorizationCodeOptions,
      accessTokenOptions: this.accessTokenOptions,
      refreshTokenOptions: this.refreshTokenOptions,
      randomJti: this.randomJti,
    });
  }

  // Authorize

  validateRedirectUri(
    redirect_uri: string | undefined,
    allowedRedirectUris: string | string[],
    errorDetails?: Omit<AuthorizeErrorResponse, "error" | "error_description">,
  ): Result<string, undefined, AuthorizeErrorResponse> {
    return validateRedirectUri(redirect_uri, allowedRedirectUris, errorDetails);
  }

  validateAuthorizeRequest(
    req: AuthorizeRequest,
    errorDetails?: Omit<AuthorizeErrorResponse, "error" | "error_description">,
  ): Result<
    Omit<NormalizedAuthorizeInput, "subject" | "redirect_uri"> & {
      redirect_uri?: string;
    },
    undefined,
    AuthorizeErrorResponse
  > {
    return validateAuthorizeRequest(req, errorDetails);
  }

  issueAuthorizationCode(
    args: NormalizedAuthorizeInput,
  ): Promise<IssueAuthorizationCodeReturn> {
    return issueAuthorizationCode(args, this.options);
  }

  // Token

  validateTokenRequest(
    req: TokenRequest & {
      accessTokenExtraClaims?: Record<string, unknown>;
      refreshTokenExtraClaims?: Record<string, unknown>;
    },
    errorDetails?: Omit<TokenErrorResponse, "error" | "error_description">,
  ): Result<NormalizedTokenInput, undefined, TokenErrorResponse> {
    return validateTokenRequest(req, errorDetails);
  }

  issueTokenGrant(
    args: NormalizedTokenInput & {
      refreshTokenExtraClaims?: Record<string, unknown>;
    },
    options?: {
      introspectAuthorizationCode?: () => MaybePromise<
        AuthorizationCodeClaims | undefined
      >;
      introspectRefreshToken?: () => MaybePromise<
        RefreshTokenClaims | undefined
      >;
    },
  ): Promise<IssueTokenGrantReturn> {
    const opts = { ...this.options, ...options };
    return issueTokenGrant(args, opts as any); // TODO: readonly type issue
  }

  // Introspection

  introspectAuthorizationCode(token: string): Promise<AuthorizationCodeClaims> {
    return introspectAuthorizationCode({
      token,
      iss: this.issuer,
      options: this.authorizationCodeOptions,
    });
  }

  introspectAccessToken(token: string): Promise<AccessTokenClaims> {
    return introspectAccessToken({
      token,
      iss: this.issuer,
      options: this.accessTokenOptions as any, // TODO: readonly type issue
    });
  }

  introspectRefreshToken(token: string): Promise<RefreshTokenClaims> {
    return introspectRefreshToken({
      token,
      iss: this.issuer,
      options: this.refreshTokenOptions,
    });
  }
}

function getPublicKeys(publicKey?: JWK | JWK[]): JWKSet {
  if (publicKey !== undefined) {
    const key = Array.isArray(publicKey) ? publicKey : [publicKey];

    return {
      keys: key.filter((key) => key.kid !== undefined && isPublicJWK(key)),
    };
  }

  return { keys: [] };
}
