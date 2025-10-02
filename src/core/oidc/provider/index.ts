export * from "./internal";
export { OAuthError } from "../../oauth";

import type { JWK, JWKSet } from "unjwt";
import { isPublicJWK } from "unjwt/utils";

import type { MaybePromise } from "../../../types";
import { deepFreeze } from "../../../utils";

import { OAuthProvider } from "../../oauth";

import type {
  Result,
  IdTokenClaims,
  AuthorizeRequest,
  AuthorizeErrorResponse,
  AuthorizationCodeClaims,
  RefreshTokenClaims,
} from "../types";
import type {
  OIDCProviderOptions,
  ResolvedIdTokenOptions,
  OIDCDiscoveryDocument,
  OIDCUserInfoProfile,
  NormalizedAuthorizeInput,
  IssueAuthorizationCodeReturn,
  NormalizedTokenInput,
  IssueTokenGrantReturn,
} from "./internal";
import {
  oidcProviderDefaults,
  buildUserInfo,
  introspectIdToken,
  validateAuthorizeRequest,
  issueAuthorizationCode,
  issueTokenGrant,
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
  private _OIDCdiscovery: OIDCDiscoveryDocument;
  private _it: ResolvedIdTokenOptions;
  private _idTokenJwkSet: JWKSet;
  private _mergedJwkSet: JWKSet;

  constructor(args: OIDCProviderOptions) {
    const { idTokenOptions, discovery, ...defaults } =
      oidcProviderDefaults(args);
    super(defaults);

    this._OIDCdiscovery = discovery;
    this._it = idTokenOptions;
    this._idTokenJwkSet = getPublicKeys(idTokenOptions.publicKey);
    this._mergedJwkSet = mergeUniqueKids(super.jwkSet, this._idTokenJwkSet);
  }

  get idTokenOptions() {
    return deepFreeze(this._it);
  }
  override get issuer() {
    return this._OIDCdiscovery.issuer;
  }
  override get discoveryDocument() {
    return deepFreeze(this._OIDCdiscovery);
  }
  override get jwkSet() {
    return {
      keys: [...this._mergedJwkSet.keys],
    };
  }
  override get options() {
    return Object.freeze({
      iss: this.issuer,
      authorizationCodeOptions: this.authorizationCodeOptions,
      accessTokenOptions: this.accessTokenOptions,
      refreshTokenOptions: this.refreshTokenOptions,
      idTokenOptions: this.idTokenOptions,
      randomJti: this.randomJti,
    });
  }

  // Discovery

  buildUserInfo<T extends Record<string, unknown>>(
    profile: OIDCUserInfoProfile,
  ): OIDCUserInfoProfile & T {
    return buildUserInfo<T>(profile);
  }

  // Authorize

  override validateAuthorizeRequest(
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

  override issueAuthorizationCode(
    args: NormalizedAuthorizeInput,
  ): Promise<IssueAuthorizationCodeReturn> {
    return issueAuthorizationCode(args, this.options);
  }

  // Token

  override issueTokenGrant(
    args: NormalizedTokenInput & {
      refreshTokenExtraClaims?: Record<string, unknown>;
      idTokenExtraClaims?: Record<string, unknown>;
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
    return issueTokenGrant(args, opts);
  }

  // Introspection

  introspectIdToken(token: string): Promise<IdTokenClaims> {
    return introspectIdToken({
      token,
      iss: this.issuer,
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
