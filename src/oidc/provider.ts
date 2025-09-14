import type { JWK, JWSSignOptions, JWSVerifyOptions } from "unjwt";
import { isJWK, isPublicJWK } from "unjwt/utils";

import { type OAuthProviderConfig, OAuthProvider } from "../oauth";
import type {
  ResolvedOIDCOptions,
  OIDCDiscoveryOptions,
  OIDCUserInfoProfile,
} from "./internal";
import {
  oidcOptionsDefaults,
  introspectIdToken,
  buildOIDCDiscoveryDocument,
  buildUserInfo,
  signIdToken,
} from "./internal";
import type { TokenErrorResponse, TokenResponse } from "../oauth/internal";

export interface OIDCProviderConfig extends OAuthProviderConfig {
  /**
   * Options for ID Tokens.
   */
  idToken: {
    privateKey: JWK;
    signOptions?: JWSSignOptions;
    verifyOptions?: JWSVerifyOptions;
  };
}

export class OIDCProvider extends OAuthProvider {
  private activePrivateIDKey: JWK;
  private oidcOptions: ResolvedOIDCOptions;

  constructor(cfg: OIDCProviderConfig) {
    const { idToken: _id, ...oauthCfg } = cfg;
    super(oauthCfg);
    this.activePrivateIDKey = cfg.idToken.privateKey;
    this.oidcOptions = oidcOptionsDefaults(cfg);
  }

  get idTokenKeyInfo(): Pick<JWK, "kid" | "alg" | "kty"> {
    const { kid, alg, kty } = this.activePrivateIDKey;
    return { kid, alg, kty };
  }

  /** Replace the public JWKS. Must contain the active key kid if set. */
  override setJwks(jwks: JWK[]): void {
    const clean = filterPublicJwks(jwks);
    const kid = this.activePrivateIDKey?.kid;
    if (kid && !clean.some((k) => k.kid === kid)) {
      throw new Error(
        "[OIDC] Provided JWKS does not include the active signing key kid",
      );
    }
    super.setJwks(clean);
  }

  /**
   * Return a public JWK by kid (searches current JWKS).
   */
  override getPublicKeyByKid(kid?: string): JWK | undefined {
    return this.getPublicJwks()?.keys?.find((k) => k.kid === kid);
  }

  rotateIDKey(newKey: JWK, newJwks?: JWK[]): void {
    if (!newKey || !isJWK(newKey)) {
      throw new Error("[OIDC] Invalid signing key");
    }
    if (!newKey.kid) {
      throw new Error("[OIDC] New signing key must include a kid for rotation");
    }
    if (newJwks) {
      if (!newJwks.some((k) => k.kid === newKey.kid)) {
        throw new Error(
          "[OIDC] Provided JWKS does not include the new signing key kid",
        );
      }
      this.setJwks(newJwks);
    } else if (this.getPublicJwks()?.keys) {
      if (!this.getPublicKeyByKid(newKey.kid)) {
        throw new Error(
          "[OIDC] Current JWKS does not contain the new key kid; provide an updated JWKS",
        );
      }
    } else {
      throw new Error(
        "[OIDC] No JWKS set; provide JWKS when rotating signing key",
      );
    }
    this.activePrivateIDKey = newKey;
  }

  // Authorization endpoint helpers (OAuth 2.1 + OIDC validation)
  override async issueAuthorizationCode() {
    // TODO: OIDC Validate authorize request via hook
    return super.issueAuthorizationCode();
  }

  override async issueAccessToken(): Promise<
    (TokenResponse & { id_token?: string }) | TokenErrorResponse
  > {
    const base = await super.issueAccessToken();
    if (!("access_token" in (base as TokenResponse)))
      return base as TokenErrorResponse;

    const tokenRes = base as TokenResponse;
    // Attach id_token only when openid scope requested
    const scope = tokenRes.scope || "";
    if (!scope.split(" ").includes("openid")) return tokenRes;

    // Introspect access token to get claims for ID Token
    const at = await this.introspectAccessToken(tokenRes.access_token);
    if (!at.active || !at.claims) return tokenRes; // shouldn't happen

    const id_token = await signIdToken(
      {
        access: tokenRes.access_token,
        // TODO: how should we handle code and nonce here?
      },
      at.claims,
      this.oidcOptions,
      this.activePrivateIDKey,
    );

    return { ...tokenRes, id_token } as TokenResponse & { id_token: string };
  }

  // Utility to introspect id tokens while validating their claims
  async introspectIdToken(token: string) {
    const at = await introspectIdToken(
      token,
      this.getPublicJwks() || this.activePrivateIDKey,
      this.oidcOptions,
    ).catch((error_) => {
      console.error(error_);
      return undefined;
    });

    if (!at?.payload) return { active: false };

    return { active: true, claims: at.payload };
  }

  /**
   * Minimal discovery document suitable for .well-known/openid-configuration.
   */
  override getDiscoveryDocument(
    options?: Omit<OIDCDiscoveryOptions, "issuer">,
  ) {
    return buildOIDCDiscoveryDocument({
      ...options,
      issuer: this.issuer,
    });
  }

  /**
   * Build a compliant UserInfo response by picking allowed standard claims from a provided profile.
   */
  buildUserInfo<T extends Record<string, unknown>>(
    profile: OIDCUserInfoProfile,
  ): OIDCUserInfoProfile & T {
    return buildUserInfo(profile);
  }
}

function filterPublicJwks(keys: JWK[]): JWK[] {
  return keys.filter((j) => isPublicJWK(j));
}
