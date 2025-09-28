export * from "./error";
export * from "./internal";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import { OAuthError } from "./error";
import type {
  TokenRequest,
  TokenErrorResponse,
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

  discovery(
    options?: Omit<BuildOAuthDiscoveryArgs, "issuer">,
  ): OAuthDiscoveryDocument {
    return buildOAuthDiscoveryDocument({ ...options, issuer: this.iss });
  }

  // Authorize

  async authorize(
    args: Pick<BuildAuthorizationCodeArgs, "req" | "claims">,
    registeredRedirectUris: string | string[],
  ): Promise<BuildAuthorizationCodeReturn> {
    const redirect_uri = validateRedirectUri(
      args.req,
      registeredRedirectUris,
      this.iss,
    );

    if (typeof redirect_uri !== "string") {
      throw new OAuthError(redirect_uri);
    }

    return buildAuthorizationCode({
      req: {
        ...args.req,
        redirect_uri,
      },
      claims: args.claims,
      iss: this.iss,
      randomJti: this.randomJti,
      options: this.acOptions,
    });
  }

  // Token

  async token(
    req: TokenRequest,
    extra?: {
      currentDate?: Date;
      accessTokenClaims?: BuildAuthorizationCodeGrantArgs["extraAccessTokenClaims"];
      refreshTokenClaims?: BuildAuthorizationCodeGrantArgs["extraRefreshTokenClaims"];
    },
  ): Promise<
    | BuildAuthorizationCodeGrantReturn
    | BuildClientCredentialsGrantReturn
    | BuildRefreshTokenGrantReturn
    | { res: TokenErrorResponse }
  > {
    const _req = validateTokenRequest(req, this.iss);

    if ("error" in _req) {
      return { res: _req };
    }

    switch (req.grant_type) {
      case "authorization_code": {
        return buildAuthorizationCodeGrant({
          req: _req as BuildAuthorizationCodeGrantArgs["req"],
          currentDate: extra?.currentDate,
          extraAccessTokenClaims: extra?.accessTokenClaims,
          extraRefreshTokenClaims: extra?.refreshTokenClaims,
          iss: this.iss,
          randomJti: this.randomJti,
          authorizationCodeOptions: this.acOptions,
          accessTokenOptions: this.atOptions,
          refreshTokenOptions: this.rtOptions,
        });
      }
      case "client_credentials": {
        return buildClientCredentialsGrant({
          req: _req as BuildClientCredentialsGrantArgs["req"],
          currentDate: extra?.currentDate,
          extraAccessTokenClaims: extra?.accessTokenClaims,
          iss: this.iss,
          randomJti: this.randomJti,
          accessTokenOptions: this.atOptions,
        });
      }
      case "refresh_token": {
        return buildRefreshTokenGrant({
          req: _req as BuildRefreshTokenGrantArgs["req"],
          currentDate: extra?.currentDate,
          extraAccessTokenClaims: extra?.accessTokenClaims,
          extraRefreshTokenClaims: extra?.refreshTokenClaims,
          iss: this.iss,
          randomJti: this.randomJti,
          accessTokenOptions: this.atOptions,
          refreshTokenOptions: this.rtOptions,
        });
      }
      default: {
        throw new OAuthError({
          error: "unsupported_grant_type",
          error_description: `The grant_type '${(req as TokenRequest).grant_type}' is not supported.`,
        });
      }
    }
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
