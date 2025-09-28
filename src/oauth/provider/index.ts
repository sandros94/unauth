export * from "./error";
export * from "./internal";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import type {
  OAuthProviderOptions,
  ResolvedAuthorizationCodeOptions,
  ResolvedAccessTokenOptions,
  ResolvedRefreshTokenOptions,
  BuildOAuthDiscoveryArgs,
  BuildAuthorizationCodeArgs,
  BuildAuthorizationCodeGrantArgs,
  BuildClientCredentialsGrantArgs,
  BuildRefreshTokenGrantArgs,
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

  discovery(options?: Omit<BuildOAuthDiscoveryArgs, "issuer">) {
    return buildOAuthDiscoveryDocument({ ...options, issuer: this.iss });
  }

  // Authorize

  validateAuthorizeRedirectUri(
    redirectUri: string | undefined,
    registeredRedirectUris: string | string[],
    state?: string,
  ) {
    return validateRedirectUri(
      { redirectUri, state },
      registeredRedirectUris,
      this.iss,
    );
  }

  async authorizationCode(
    args: Pick<BuildAuthorizationCodeArgs, "req" | "claims">,
  ) {
    return buildAuthorizationCode({
      req: args.req,
      claims: args.claims,
      iss: this.iss,
      randomJti: this.randomJti,
      options: this.acOptions,
    });
  }

  // Token

  validateTokenRequest(req: unknown) {
    return validateTokenRequest(req, this.iss);
  }

  async authorizationCodeGrant(
    args: Omit<
      BuildAuthorizationCodeGrantArgs,
      "iss" | "randomJti" | "accessTokenOptions" | "refreshTokenOptions"
    >,
  ) {
    return buildAuthorizationCodeGrant({
      req: args.req,
      codeClaims: args.codeClaims,
      currentDate: args.currentDate,
      extraAccessTokenClaims: args.extraAccessTokenClaims,
      extraRefreshTokenClaims: args.extraRefreshTokenClaims,
      iss: this.iss,
      randomJti: this.randomJti,
      accessTokenOptions: this.atOptions,
      refreshTokenOptions: this.rtOptions,
    });
  }

  async clientCredentialsGrant(
    args: Omit<
      BuildClientCredentialsGrantArgs,
      "iss" | "randomJti" | "accessTokenOptions"
    >,
  ) {
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
  ) {
    return buildRefreshTokenGrant({
      req: args.req,
      currentDate: args.currentDate,
      refreshTokenClaims: args.refreshTokenClaims,
      extraAccessTokenClaims: args.extraAccessTokenClaims,
      extraRefreshTokenClaims: args.extraRefreshTokenClaims,
      iss: this.iss,
      randomJti: this.randomJti,
      accessTokenOptions: this.atOptions,
      refreshTokenOptions: this.rtOptions,
    });
  }

  // Introspection

  introspectAuthorizationCode(token: string) {
    return introspectAuthorizationCode({
      token,
      iss: this.iss,
      options: this.acOptions,
    });
  }

  introspectAccessToken(token: string) {
    return introspectAccessToken({
      token,
      iss: this.iss,
      options: this.atOptions,
    });
  }

  introspectRefreshToken(token: string) {
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
