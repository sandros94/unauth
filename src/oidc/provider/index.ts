export * from "./internal";
export { OAuthError } from "../../oauth";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import { OAuthProvider } from "../../oauth";
import type {
  ResolvedAccessTokenOptions,
  ResolvedAuthorizationCodeOptions,
  ResolvedRefreshTokenOptions,
} from "../../oauth/provider/internal";

import type { IdTokenClaims } from "../types";
import type {
  OIDCProviderOptions,
  ResolvedIdTokenOptions,
  BuildAuthorizationCodeArgs,
  BuildAuthorizationCodeGrantArgs,
  BuildAuthorizationCodeGrantReturn,
  BuildAuthorizationCodeReturn,
  BuildOIDCDiscoveryArgs,
  BuildRefreshTokenGrantArgs,
  BuildRefreshTokenGrantReturn,
  OIDCDiscoveryDocument,
  OIDCUserInfoProfile,
} from "./internal";
import {
  oidcProviderDefaults,
  buildAuthorizationCode,
  buildAuthorizationCodeGrant,
  buildOIDCDiscoveryDocument,
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

  override async authorizationCode(
    args: Pick<BuildAuthorizationCodeArgs, "req" | "claims">,
  ): Promise<BuildAuthorizationCodeReturn> {
    return buildAuthorizationCode({
      req: args.req,
      claims: args.claims,
      iss: this.iss,
      randomJti: this.randomJtiFn,
      options: this.authorizationCodeOptions,
    });
  }

  // Token

  override async authorizationCodeGrant(
    args: Omit<
      BuildAuthorizationCodeGrantArgs,
      | "iss"
      | "randomJti"
      | "authorizationCodeOptions"
      | "accessTokenOptions"
      | "refreshTokenOptions"
      | "idTokenOptions"
    >,
  ): Promise<BuildAuthorizationCodeGrantReturn> {
    return buildAuthorizationCodeGrant({
      req: args.req,
      currentDate: args.currentDate,
      extraIdTokenClaims: args.extraIdTokenClaims,
      extraAccessTokenClaims: args.extraAccessTokenClaims,
      extraRefreshTokenClaims: args.extraRefreshTokenClaims,
      iss: this.iss,
      randomJti: this.randomJtiFn,
      authorizationCodeOptions: this.authorizationCodeOptions,
      accessTokenOptions: this.accessTokenOptions,
      refreshTokenOptions: this.refreshTokenOptions,
      idTokenOptions: this.idTokenOptions,
    });
  }

  override async refreshTokenGrant(
    args: Omit<
      BuildRefreshTokenGrantArgs,
      | "iss"
      | "randomJti"
      | "accessTokenOptions"
      | "refreshTokenOptions"
      | "idTokenOptions"
    >,
  ): Promise<BuildRefreshTokenGrantReturn> {
    return buildRefreshTokenGrant({
      req: args.req,
      currentDate: args.currentDate,
      extraIdTokenClaims: args.extraIdTokenClaims,
      extraAccessTokenClaims: args.extraAccessTokenClaims,
      extraRefreshTokenClaims: args.extraRefreshTokenClaims,
      iss: this.iss,
      randomJti: this.randomJtiFn,
      accessTokenOptions: this.accessTokenOptions,
      refreshTokenOptions: this.refreshTokenOptions,
      idTokenOptions: this.idTokenOptions,
    });
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
