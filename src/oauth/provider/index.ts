export * from "./error";
export * from "./internal";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import type {
  AuthorizeRequest,
  AuthorizeErrorResponse,
  TokenRequest,
  AuthorizationCodeClaims,
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
  BuildAuthorizationCodeArgs,
  BuildAuthorizationCodeReturn,
  BuildAuthorizationCodeGrantArgs,
  BuildAuthorizationCodeGrantReturn,
  BuildClientCredentialsGrantArgs,
  BuildClientCredentialsGrantReturn,
  BuildRefreshTokenGrantArgs,
  BuildRefreshTokenGrantReturn,
} from "./internal";
import {
  oauthProviderDefaults,
  buildOAuthDiscoveryDocument,
  buildAuthorizationCode,
  validateRedirectUri,
  validateTokenRequest,
  buildAuthorizationCodeGrant,
  buildClientCredentialsGrant,
  buildRefreshTokenGrant,
  introspectAuthorizationCode,
  introspectAccessToken,
  introspectRefreshToken,
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
  readonly iss: string;
  private readonly acOptions: ResolvedAuthorizationCodeOptions;
  private readonly rtOptions: ResolvedRefreshTokenOptions;
  private readonly atOptions: ResolvedAccessTokenOptions;
  private readonly randomJti: () => string;
  readonly accessTokenJwkSet: JWKSet;
  readonly jwkSet: JWKSet;

  constructor(args: OAuthProviderOptions) {
    const opts = oauthProviderDefaults(args);

    this.iss = opts.issuer;
    this.randomJti = opts.randomJti;
    this.acOptions = opts.authorizationCodeOptions;
    this.rtOptions = opts.refreshTokenOptions;
    this.atOptions = opts.accessTokenOptions;
    this.accessTokenJwkSet = getPublicKeys(this.atOptions.publicKey);
    this.jwkSet = this.accessTokenJwkSet;
  }

  // Discovery

  discovery(options?: Omit<BuildOAuthDiscoveryArgs, "issuer">): OAuthDiscoveryDocument {
    return buildOAuthDiscoveryDocument({ ...options, issuer: this.iss });
  }

  // Authorize

  validateAuthorizeRedirectUri(
    req: Pick<AuthorizeRequest, "redirect_uri" | "state">,
    registeredRedirectUris: string | string[],
  ): string | AuthorizeErrorResponse {
    return validateRedirectUri(req, registeredRedirectUris, this.iss);
  }

  async authorizationCode(
    args: Pick<BuildAuthorizationCodeArgs, "req" | "claims">,
  ): Promise<BuildAuthorizationCodeReturn> {
    return buildAuthorizationCode({
      req: args.req,
      claims: args.claims,
      iss: this.iss,
      randomJti: this.randomJti,
      options: this.acOptions,
    });
  }

  // Token

  validateTokenRequest(req: unknown): req is TokenRequest {
    return validateTokenRequest(req, this.iss);
  }

  async authorizationCodeGrant(
    args: Omit<
      BuildAuthorizationCodeGrantArgs,
      | "iss"
      | "randomJti"
      | "authorizationCodeOptions"
      | "accessTokenOptions"
      | "refreshTokenOptions"
    >,
  ): Promise<BuildAuthorizationCodeGrantReturn> {
    return buildAuthorizationCodeGrant({
      req: args.req,
      currentDate: args.currentDate,
      extraAccessTokenClaims: args.extraAccessTokenClaims,
      extraRefreshTokenClaims: args.extraRefreshTokenClaims,
      iss: this.iss,
      randomJti: this.randomJti,
      authorizationCodeOptions: this.acOptions,
      accessTokenOptions: this.atOptions,
      refreshTokenOptions: this.rtOptions,
    });
  }

  async clientCredentialsGrant(
    args: Omit<
      BuildClientCredentialsGrantArgs,
      "iss" | "randomJti" | "accessTokenOptions"
    >,
  ): Promise<BuildClientCredentialsGrantReturn> {
    return buildClientCredentialsGrant({
      req: args.req,
      currentDate: args.currentDate,
      extraAccessTokenClaims: args.extraAccessTokenClaims,
      iss: this.iss,
      randomJti: this.randomJti,
      accessTokenOptions: this.atOptions,
    });
  }

  async refreshTokenGrant(
    args: Omit<
      BuildRefreshTokenGrantArgs,
      "iss" | "randomJti" | "accessTokenOptions" | "refreshTokenOptions"
    >,
  ): Promise<BuildRefreshTokenGrantReturn> {
    return buildRefreshTokenGrant({
      req: args.req,
      currentDate: args.currentDate,
      extraAccessTokenClaims: args.extraAccessTokenClaims,
      extraRefreshTokenClaims: args.extraRefreshTokenClaims,
      iss: this.iss,
      randomJti: this.randomJti,
      accessTokenOptions: this.atOptions,
      refreshTokenOptions: this.rtOptions,
    });
  }

  // Introspection

  introspectAuthorizationCode(token: string): Promise<AuthorizationCodeClaims> {
    return introspectAuthorizationCode({
      token,
      iss: this.iss,
      options: this.acOptions,
    });
  }

  introspectAccessToken(token: string): Promise<AccessTokenClaims> {
    return introspectAccessToken({
      token,
      iss: this.iss,
      options: this.atOptions,
    });
  }

  introspectRefreshToken(token: string): Promise<RefreshTokenClaims> {
    return introspectRefreshToken({
      token,
      iss: this.iss,
      options: this.rtOptions,
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
