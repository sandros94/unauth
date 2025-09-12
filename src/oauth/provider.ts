import { isPublicJWK, isJWK } from "unjwt/utils";
import type { JWK } from "unjwt";

import type {
  OAuthOptions,
  ResolvedOAuthOptions,
  AuthorizationCodeOptions,
  AccessTokenOptions,
  RefreshTokenOptions,
  OAuthDiscoveryOptions,
} from "./internal";
import {
  oauthOptionsDefaults,
  issueAuthorizationCode,
  issueAccessToken,
  introspectAuthorizationCode,
  introspectAccessToken,
  introspectRefreshToken,
  buildOAuthDiscoveryDocument,
} from "./internal";

/**
 * Configuration for the OAuth service wrapper.
 */
export interface OAuthProviderConfig extends OAuthOptions {
  /** Optional initial public JWKS. Private keys will be filtered. */
  jwks?: JWK[];
}

export interface IntrospectOptions {
  audience?: string | string[];
}

export class OAuthProvider {
  private activePrivateACKey: string | JWK;
  private activePrivateATKey: JWK;
  private activePrivateRTKey: string | JWK;
  private _jwks?: JWK[];
  private options: ResolvedOAuthOptions;

  private get authorizationCodeOptions(): AuthorizationCodeOptions {
    return this.options.authorizationCode;
  }
  private get accessTokenOptions(): AccessTokenOptions {
    return this.options.accessToken;
  }
  private get refreshTokenOptions(): RefreshTokenOptions {
    return this.options.refreshToken;
  }

  constructor(config: OAuthProviderConfig) {
    this.options = oauthOptionsDefaults(config);
    this.activePrivateACKey = config.authorizationCode.privateKey;
    this.activePrivateATKey = config.accessToken.privateKey;
    this.activePrivateRTKey = config.refreshToken.privateKey;
    this._jwks = config.jwks ? filterPublicJwks(config.jwks) : undefined;
  }

  // Basic getters
  get issuer(): string {
    return this.options.issuer;
  }
  get availableScopes(): string[] | undefined {
    return this.options.availableScopes;
  }
  get defaultScope(): string | undefined {
    return this.options.defaultScope;
  }

  /** Header-safe info about the active signing key for access tokens. */
  get accessKeyInfo(): Pick<JWK, "kid" | "alg" | "kty"> {
    const { kid, alg, kty } = this.activePrivateATKey;
    return { kid, alg, kty };
  }

  /** Replace the public JWKS. Must contain the active key kid if set. */
  setJwks(jwks: JWK[]): void {
    const clean = filterPublicJwks(jwks);
    const kid = this.activePrivateATKey?.kid;
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
    this.activePrivateATKey = newKey;
  }

  /** Rotate the active authorization code encryption key. */
  rotateAuthorizationCodeKey(newKey: string | JWK): void {
    if (!newKey || (!isJWK(newKey) && typeof newKey !== "string")) {
      throw new Error("[OAuth] Invalid encryption key");
    }
    this.activePrivateACKey = newKey;
  }

  /** Rotate the active refresh token encryption key. */
  rotateRefreshTokenKey(newKey: string | JWK): void {
    if (!newKey || (!isJWK(newKey) && typeof newKey !== "string")) {
      throw new Error("[OAuth] Invalid encryption key");
    }
    this.activePrivateRTKey = newKey;
  }

  // Authorization endpoint helpers
  async issueAuthorizationCode() {
    return issueAuthorizationCode(this.options, this.activePrivateACKey);
  }

  // Token endpoint helpers
  async issueAccessToken() {
    return issueAccessToken(this.options, {
      authorizationCode: this.activePrivateACKey,
      accessToken: this.activePrivateATKey,
      refreshToken: this.activePrivateRTKey,
    });
  }

  // Utility to introspect refresh tokens while validating their claims
  async introspectAuthorizationCode(token: string) {
    const ac = await introspectAuthorizationCode(
      token,
      this.activePrivateACKey,
      this.options,
    ).catch(() => undefined);

    if (!ac?.payload) return { active: false };

    return { active: true, claims: ac.payload };
  }

  // Utility to introspect access tokens while validating their claims
  async introspectAccessToken(token: string) {
    const at = await introspectAccessToken(
      token,
      this.getPublicJwks() || this.activePrivateATKey,
      this.options,
    ).catch(() => undefined);

    if (!at?.payload) return { active: false };

    return { active: true, claims: at.payload };
  }

  // Utility to introspect refresh tokens while validating their claims
  async introspectRefreshToken(token: string) {
    const rt = await introspectRefreshToken(
      token,
      this.activePrivateRTKey,
      this.options,
    ).catch(() => undefined);

    if (!rt?.payload) return { active: false };

    return { active: true, claims: rt.payload };
  }

  /**
   * Minimal discovery document suitable for .well-known/oauth-configuration.
   */
  getDiscoveryDocument(options?: Omit<OAuthDiscoveryOptions, "issuer">) {
    return buildOAuthDiscoveryDocument({
      ...options,
      issuer: this.issuer,
    });
  }
}

function filterPublicJwks(keys: JWK[]): JWK[] {
  return keys.filter((j) => isPublicJWK(j));
}
