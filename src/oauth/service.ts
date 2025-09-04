import type {
  JWK,
  JWSSignOptions,
  JWSVerifyOptions,
  JWEEncryptOptions,
  JWEDecryptOptions,
  JWTClaims,
} from "unjwt";
import { isPublicJWK, isJWK } from "unjwt/utils";

import type { MaybePromise } from "../types";
import type {
  OAuthAuthorizeOptions,
  OAuthAuthorizeRequest,
  OAuthAuthorizeSuccess,
  OAuthAuthorizeError,
} from "./authorize";
import {
  authorizeError as _authorizeError,
  buildAuthorizationCode,
  buildAuthorizeRedirect as _buildAuthorizeRedirect,
} from "./authorize";
import {
  oAuthAuthorizationCode,
  oAuthClientCredentials,
  oAuthRefreshToken,
} from "./token";
import type {
  OAuthTokenOptions,
  OAuthTokenRequest,
  OAuthTokenResponse,
} from "./token";
import type {
  ResolvedAuthorizeOptions,
  ResolvedTokenOptions,
} from "./defaults";
import {
  withAuthorizeDefaults,
  withTokenDefaults,
} from "./defaults";
import type {
  OAuthAccessTokenClaims,
  OAuthAuthorizationCodeClaims,
  OAuthRefreshTokenClaims,
} from "./types";
import {
  type OAuthDiscoveryOptions,
  buildDiscoveryDocument,
} from "./discovery";
import { introspectToken } from "./utils";
import { revokeToken } from "./token";

/**
 * Configuration for the OAuth service wrapper.
 */
export interface OAuthProviderConfig
  extends Omit<
    OAuthTokenOptions,
    | "jwsPrivateKey"
    | "jweSecret"
    | "signOptions"
    | "verifyOptions"
    | "encryptOptions"
    | "decryptOptions"
  > {
  /** Optional initial public JWKS. Private keys will be filtered. */
  jwks?: JWK[];
  /**
   * Options for Access Tokens.
   */
  accessToken: {
    privateKey: JWK;
    signOptions?: JWSSignOptions;
    verifyOptions?: JWSVerifyOptions;
  };
  /**
   * Options for Refresh Tokens.
   */
  refreshToken: {
    privateKey: string | JWK;
    encryptOptions?: JWEEncryptOptions;
    decryptOptions?: JWEDecryptOptions;
  };
}

export interface IntrospectOptions {
  audience?: string | string[];
}

export class OAuthProvider {
  private activePrivateRefreshKey: string | JWK;
  private activePrivateAccessKey: JWK;
  private _jwks?: JWK[];
  private get authorizeOptions(): OAuthAuthorizeOptions {
    return {
      issuer: this.config.issuer,
      jweSecret: this.activePrivateRefreshKey,
      encryptOptions: this.config.refreshToken?.encryptOptions,
      randomJti: this.config.randomJti,
      defaultScope: this.config.defaultScope,
      availableScopes: this.config.availableScopes,
    };
  }
  private get tokenOptions(): OAuthTokenOptions {
    return {
      issuer: this.config.issuer,
      jweSecret: this.activePrivateRefreshKey,
      jwsPrivateKey: this.activePrivateAccessKey,
      decryptOptions: this.config.refreshToken?.decryptOptions,
      encryptOptions: this.config.refreshToken?.encryptOptions,
      signOptions: this.config.accessToken?.signOptions,
      verifyOptions: this.config.accessToken?.verifyOptions,
      randomJti: this.config.randomJti,
      defaultScope: this.config.defaultScope,
      availableScopes: this.config.availableScopes,
    };
  }

  constructor(private readonly config: OAuthProviderConfig) {
    this.activePrivateAccessKey = config.accessToken.privateKey;
    this.activePrivateRefreshKey = config.refreshToken.privateKey;
    this._jwks = config.jwks ? filterPublicJwks(config.jwks) : undefined;
  }

  // Basic getters
  get issuer(): string {
    return this.config.issuer;
  }
  get availableScopes(): string[] | undefined {
    return this.config.availableScopes;
  }
  get defaultScope(): string | undefined {
    return this.config.defaultScope;
  }

  /** Header-safe info about the active signing key for access tokens. */
  get accessKeyInfo(): Pick<JWK, "kid" | "alg" | "kty"> {
    const { kid, alg, kty } = this.activePrivateAccessKey;
    return { kid, alg, kty };
  }

  /** Replace the public JWKS. Must contain the active key kid if set. */
  setJwks(jwks: JWK[]): void {
    const clean = filterPublicJwks(jwks);
    const kid = this.activePrivateAccessKey?.kid;
    if (kid && !clean.some((k) => k.kid === kid)) {
      throw new Error(
        "[OAuth] Provided JWKS does not include the active signing key kid",
      );
    }
    this._jwks = clean;
  }

  /**
   * Public JWKS payload (only public keys).
   */
  getPublicJwks(): { keys: JWK[] } | undefined {
    const keys = this._jwks;
    return keys ? { keys } : undefined;
  }

  /**
   * Return a public JWK by kid (searches current JWKS).
   */
  getPublicKeyByKid(kid?: string): JWK | undefined {
    return this.getPublicJwks()?.keys?.find((k) => k.kid === kid);
  }

  /** Rotate the active signing key for access tokens. Optionally update JWKS; JWKS must include the new key's kid. */
  rotateAccessKey(newKey: JWK, newJwks?: JWK[]): void {
    if (!newKey || !isJWK(newKey)) {
      throw new Error("[OAuth] Invalid signing key");
    }
    if (!newKey.kid) {
      throw new Error(
        "[OAuth] New signing key must include a kid for rotation",
      );
    }
    if (newJwks) {
      if (!newJwks.some((k) => k.kid === newKey.kid)) {
        throw new Error(
          "[OAuth] Provided JWKS does not include the new signing key kid",
        );
      }
      this.setJwks(newJwks);
    } else if (this.getPublicJwks()?.keys) {
      if (!this.getPublicKeyByKid(newKey.kid)) {
        throw new Error(
          "[OAuth] Current JWKS does not contain the new key kid; provide an updated JWKS",
        );
      }
    } else {
      throw new Error(
        "[OAuth] No JWKS set; provide JWKS when rotating signing key",
      );
    }
    this.activePrivateAccessKey = newKey;
  }

  /** Rotate the active encryption key. */
  rotateRefreshKey(newKey: string | JWK): void {
    if (!newKey || (!isJWK(newKey) && typeof newKey !== "string")) {
      throw new Error("[OAuth] Invalid encryption key");
    }
    this.activePrivateRefreshKey = newKey;
  }

  // Authorization endpoint helpers
  async authorize(
    req: OAuthAuthorizeRequest,
    cb?: (
      req: OAuthAuthorizeRequest,
      opts: ResolvedAuthorizeOptions,
    ) => MaybePromise<
      Partial<JWTClaims> & {
        sub: string;
        scope?: string;
        client_id?: string;
      }
    >,
  ): Promise<OAuthAuthorizeSuccess> {
    return buildAuthorizationCode(req, this.authorizeOptions, cb);
  }

  buildAuthorizeRedirect<T extends string | URL>(
    redirectUri: T,
    result: OAuthAuthorizeSuccess | OAuthAuthorizeError,
  ): T {
    return _buildAuthorizeRedirect<T>(redirectUri, result);
  }

  authorizeError(
    error: OAuthAuthorizeError["error"],
    description?: string,
    state?: string,
  ): OAuthAuthorizeError {
    return _authorizeError(error, description, state);
  }

  // Token endpoint helpers
  async tokenClientCredentials(
    req: Extract<OAuthTokenRequest, { grant_type: "client_credentials" }>,
    cb: (
      opts: ResolvedTokenOptions,
    ) => MaybePromise<JWTClaims & { scope: string }>,
  ): Promise<OAuthTokenResponse> {
    return oAuthClientCredentials(req, this.tokenOptions, cb);
  }

  async tokenAuthorizationCode(
    req: Extract<OAuthTokenRequest, { grant_type: "authorization_code" }>,
    cb?: (
      claims: OAuthAuthorizationCodeClaims,
      opts: ResolvedTokenOptions,
    ) => MaybePromise<{
      accessTokenClaims: JWTClaims & { scope?: string };
      refreshTokenClaims: JWTClaims & { scope?: string };
      onCodeUsed?: (jti: string) => MaybePromise<void>;
    }>,
  ): Promise<OAuthTokenResponse> {
    return oAuthAuthorizationCode(req, this.tokenOptions, cb);
  }

  async tokenRefreshToken(
    req: Extract<OAuthTokenRequest, { grant_type: "refresh_token" }>,
    cb?: (
      claims: OAuthRefreshTokenClaims,
      opts: ResolvedTokenOptions,
    ) => MaybePromise<{
      accessTokenClaims: JWTClaims & { scope?: string };
      refreshTokenClaims: JWTClaims & { scope?: string };
      onRefreshUsed?: (jti: string) => MaybePromise<void>;
    }>,
  ): Promise<OAuthTokenResponse> {
    return oAuthRefreshToken(req, this.tokenOptions, cb);
  }

  // Utility to introspect access tokens while validating their claims
  async introspectAccessToken(token: string, options?: IntrospectOptions) {
    const { expiresIn } = withTokenDefaults(this.tokenOptions).signOptions;
    return introspectToken<OAuthAccessTokenClaims>(token, {
      issuer: this.config.issuer,
      jwsPrivateKey: this.activePrivateAccessKey,
      verifyOptions: {
        maxTokenAge: expiresIn,
        ...this.config.accessToken?.verifyOptions,
        ...options,
      },
    });
  }

  // Utility to introspect refresh tokens while validating their claims
  async introspectRefreshToken(token: string, options?: IntrospectOptions) {
    const { expiresIn } = withAuthorizeDefaults(this.tokenOptions).encryptOptions;
    return introspectToken<OAuthRefreshTokenClaims>(token, {
      issuer: this.config.issuer,
      jweSecret: this.activePrivateRefreshKey,
      decryptOptions: {
        maxTokenAge: expiresIn,
        ...this.config.refreshToken?.decryptOptions,
        ...options,
      },
    });
  }

  /**
   * Minimal token revocation helper. Extracts jti and calls provided hook.
   */
  async revoke(
    token: string,
    kind: "access" | "refresh" | "code",
    cb: { onRevoke: (claims: { jti: string, iat: number, exp: number }) => MaybePromise<void> },
  ): Promise<void> {
    await revokeToken(token, kind, this.tokenOptions, cb);
  }

  /**
   * Minimal discovery document suitable for .well-known/oauth-configuration.
   */
  getDiscoveryDocument(options?: Omit<OAuthDiscoveryOptions, "issuer">) {
    return buildDiscoveryDocument({
      ...options,
      issuer: this.issuer,
    });
  }
}

function filterPublicJwks(keys: JWK[]): JWK[] {
  return keys.filter((j) => isPublicJWK(j));
}
