export * from "./error";
export * from "./internal";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import { deepFreeze } from "../../utils";

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
  BuildOAuthDiscoveryArgs,
  NormalizedAuthorizeInput,
  IssueAuthorizationCodeReturn,
  NormalizedTokenInput,
  NormalizedAuthorizationCodeGrantInput,
  NormalizedClientCredentialsGrantInput,
  NormalizedRefreshTokenGrantInput,
  IssueAuthorizationCodeGrantReturn,
  IssueClientCredentialsGrantReturn,
  IssueRefreshTokenGrantReturn,
} from "./internal";
import {
  oauthProviderDefaults,
  buildOAuthDiscoveryDocument,
  introspectAuthorizationCode,
  introspectAccessToken,
  introspectRefreshToken,
  validateRedirectUri,
  validateAuthorizeRequest,
  issueAuthorizationCode,
  validateTokenRequest,
  issueAuthorizationCodeGrant,
  issueClientCredentialsGrant,
  issueRefreshTokenGrant,
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
  private _iss: string;
  private _randomJti: () => string;
  private _jwkSet: JWKSet;

  constructor(opts: OAuthProviderOptions) {
    const r = oauthProviderDefaults(opts);
    this._iss = r.issuer;
    this._randomJti = r.randomJti;
    this._ac = r.authorizationCodeOptions;
    this._rt = r.refreshTokenOptions;
    this._at = r.accessTokenOptions;
    this._jwkSet = getPublicKeys(r.accessTokenOptions.publicKey);
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
  get issuer() {
    return this._iss;
  }
  get randomJti() {
    return this._randomJti;
  }
  get jwkSet() {
    return {
      keys: [...this._jwkSet.keys],
    };
  }
  get options() {
    return {
      iss: this.issuer,
      authorizationCodeOptions: this.authorizationCodeOptions,
      accessTokenOptions: this.accessTokenOptions,
      refreshTokenOptions: this.refreshTokenOptions,
      randomJti: this.randomJti,
    };
  }

  // Discovery

  discovery(
    options?: Omit<BuildOAuthDiscoveryArgs, "issuer">,
  ): OAuthDiscoveryDocument {
    return buildOAuthDiscoveryDocument({ ...options, issuer: this.issuer });
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
    Omit<NormalizedAuthorizeInput, "subject" | "redirect_uri">,
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

  issueAuthorizationCodeGrant(
    args: NormalizedAuthorizationCodeGrantInput,
  ): Promise<IssueAuthorizationCodeGrantReturn> {
    return issueAuthorizationCodeGrant(args, this.options);
  }

  issueClientCredentialsGrant(
    args: NormalizedClientCredentialsGrantInput,
  ): Promise<IssueClientCredentialsGrantReturn> {
    return issueClientCredentialsGrant(args, this.options);
  }

  issueRefreshTokenGrant(
    args: NormalizedRefreshTokenGrantInput,
  ): Promise<IssueRefreshTokenGrantReturn> {
    return issueRefreshTokenGrant(args, this.options);
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
      options: this.accessTokenOptions,
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
