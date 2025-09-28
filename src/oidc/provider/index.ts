export * from "./internal";
export { OAuthError } from "../../oauth";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import type {
  TokenRequest,
  TokenErrorResponse,
  ResolvedAccessTokenOptions,
  ResolvedAuthorizationCodeOptions,
  ResolvedRefreshTokenOptions,
} from "../../oauth";
import { OAuthProvider, OAuthError } from "../../oauth";

import type { IdTokenClaims } from "../types";
import type {
  OIDCProviderOptions,
  ResolvedIdTokenOptions,
  BuildAuthorizationCodeArgs,
  BuildAuthorizationCodeGrantArgs,
  BuildAuthorizationCodeGrantReturn,
  BuildClientCredentialsGrantReturn,
  BuildAuthorizationCodeReturn,
  BuildOIDCDiscoveryArgs,
  BuildRefreshTokenGrantReturn,
  OIDCDiscoveryDocument,
  OIDCUserInfoProfile,
} from "./internal";
import {
  oidcProviderDefaults,
  validateRedirectUri,
  validateTokenRequest,
  buildOIDCDiscoveryDocument,
  buildAuthorizationCode,
  buildAuthorizationCodeGrant,
  buildClientCredentialsGrant,
  buildRefreshTokenGrant,
  buildUserInfo,
  introspectIdToken,
} from "./internal";

/**
 * OIDCProvider
 *
 * A thin convenience wrapper over the low-level helpers exported from this module.
 * It shares a common issuer and token options across authorize, token, and
 * introspection helpers. All standalone helpers remain exported above; this class
 * is purely ergonomic and does not add new logic.
 */
export class OIDCProvider extends OAuthProvider {
  private readonly authorizationCodeOptions: ResolvedAuthorizationCodeOptions;
  private readonly refreshTokenOptions: ResolvedRefreshTokenOptions;
  private readonly accessTokenOptions: ResolvedAccessTokenOptions;
  private readonly idTokenOptions: ResolvedIdTokenOptions;
  private readonly randomJtiFn: () => string;
  readonly idTokenJwkSet: JWKSet;
  override readonly jwkSet: JWKSet;

  constructor(args: OIDCProviderOptions) {
    const { idTokenOptions, ...defaults } = oidcProviderDefaults(args);

    super(defaults);
    this.authorizationCodeOptions = defaults.authorizationCodeOptions;
    this.refreshTokenOptions = defaults.refreshTokenOptions;
    this.accessTokenOptions = defaults.accessTokenOptions;
    this.randomJtiFn = defaults.randomJti;
    this.idTokenJwkSet = getPublicKeys(idTokenOptions.publicKey);
    this.jwkSet = mergeUniqueKids(this.accessTokenJwkSet, this.idTokenJwkSet);

    this.idTokenOptions = idTokenOptions;
  }

  // Discovery

  override discovery(
    options?: Omit<BuildOIDCDiscoveryArgs, "issuer">,
  ): OIDCDiscoveryDocument {
    return buildOIDCDiscoveryDocument({ ...options, issuer: this.iss });
  }

  buildUserInfo<T extends Record<string, unknown>>(
    profile: OIDCUserInfoProfile,
  ): OIDCUserInfoProfile & T {
    return buildUserInfo<T>(profile);
  }

  // Authorize

  override async authorize(
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
      randomJti: this.randomJtiFn,
      options: this.authorizationCodeOptions,
    });
  }

  // Token

  override async token(
    req: TokenRequest,
    extra?: {
      currentDate?: Date;
      accessTokenClaims?: BuildAuthorizationCodeGrantArgs["extraAccessTokenClaims"];
      refreshTokenClaims?: BuildAuthorizationCodeGrantArgs["extraRefreshTokenClaims"];
      idTokenClaims?: BuildAuthorizationCodeGrantArgs["extraIdTokenClaims"];
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
          req,
          currentDate: extra?.currentDate,
          extraAccessTokenClaims: extra?.accessTokenClaims,
          extraRefreshTokenClaims: extra?.refreshTokenClaims,
          extraIdTokenClaims: extra?.idTokenClaims,
          iss: this.iss,
          randomJti: this.randomJtiFn,
          authorizationCodeOptions: this.authorizationCodeOptions,
          accessTokenOptions: this.accessTokenOptions,
          refreshTokenOptions: this.refreshTokenOptions,
          idTokenOptions: this.idTokenOptions,
        });
      }
      case "client_credentials": {
        return buildClientCredentialsGrant({
          req,
          currentDate: extra?.currentDate,
          extraAccessTokenClaims: extra?.accessTokenClaims,
          iss: this.iss,
          randomJti: this.randomJtiFn,
          accessTokenOptions: this.accessTokenOptions,
        });
      }
      case "refresh_token": {
        return buildRefreshTokenGrant({
          req,
          currentDate: extra?.currentDate,
          extraAccessTokenClaims: extra?.accessTokenClaims,
          extraRefreshTokenClaims: extra?.refreshTokenClaims,
          extraIdTokenClaims: extra?.idTokenClaims,
          iss: this.iss,
          randomJti: this.randomJtiFn,
          accessTokenOptions: this.accessTokenOptions,
          refreshTokenOptions: this.refreshTokenOptions,
          idTokenOptions: this.idTokenOptions,
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

  introspectIdToken(token: string): Promise<IdTokenClaims> {
    return introspectIdToken({
      token,
      iss: this.iss,
      options: this.idTokenOptions,
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

function mergeUniqueKids(a: JWKSet, b: JWKSet): JWKSet {
  const map = new Map<string, JWK>();

  for (const key of a.keys) {
    if (key.kid !== undefined) {
      map.set(key.kid, key);
    }
  }

  for (const key of b.keys) {
    if (key.kid !== undefined && !map.has(key.kid)) {
      map.set(key.kid, key);
    }
  }

  return { keys: [...map.values()] };
}
