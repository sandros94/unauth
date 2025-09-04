import type { JWK, JWSSignOptions, JWSVerifyOptions, JWTClaims } from "unjwt";
import { verify } from "unjwt/jws";
import { isJWK, isPublicJWK } from "unjwt/utils";

import { type OAuthProviderConfig, OAuthProvider } from "../oauth/service";
import type { MaybePromise } from "../types";
import type { OAuthAuthorizeSuccess } from "../oauth/authorize";
import type { ResolvedAuthorizeOptions } from "../oauth/defaults";
import type { OIDCAuthorizeRequest } from "./authorize";
import { validateOIDCAuthorizeRequest } from "./authorize";
import { buildIdToken } from "./id-token";
import type { OIDCBuildIdTokenArgs, OIDCIdTokenClaims } from "./types";
import { type OIDCDiscoveryOptions, buildDiscoveryDocument } from "./discovery";
import { type OIDCUserInfoProfile, buildUserInfo } from "./userinfo";

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
  private _oidcJwks?: JWK[];

  constructor(private readonly cfg: OIDCProviderConfig) {
    const { idToken: _id, ...oauthCfg } = cfg;
    super(oauthCfg);
    this.activePrivateIDKey = cfg.idToken.privateKey;
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
    // Store only OIDC keys; OAuth keys are managed by the parent and merged on read.
    this._oidcJwks = clean;
  }

  /**
   * Public JWKS payload (only public keys).
   */
  override getPublicJwks(): { keys: JWK[] } | undefined {
    const oauthKeys = super.getPublicJwks()?.keys || [];
    const oidcKeys = this._oidcJwks || [];
    if (oauthKeys.length === 0 && oidcKeys.length === 0) return undefined;
    // Merge by kid to avoid duplicates
    const byKid = new Map<string | undefined, JWK>();
    for (const k of [...oauthKeys, ...oidcKeys]) {
      byKid.set(k.kid, k);
    }
    return { keys: [...byKid.values()] };
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
  override async authorize(
    req: OIDCAuthorizeRequest,
    cb?: (
      req: OIDCAuthorizeRequest,
      opts: ResolvedAuthorizeOptions,
    ) => MaybePromise<
      Partial<JWTClaims> & {
        sub: string;
        scope?: string | undefined;
        client_id?: string | undefined;
      }
    >,
  ): Promise<OAuthAuthorizeSuccess> {
    validateOIDCAuthorizeRequest(req);
    return super.authorize(req, cb);
  }

  // OIDC: Build ID Token
  async buildIdToken(
    args: OIDCBuildIdTokenArgs,
    cb?: (
      args: OIDCBuildIdTokenArgs,
      opts: {
        issuer: string;
        jwsKey: JWK;
        signOptions: JWSSignOptions & { expiresIn: number };
      },
    ) => MaybePromise<Partial<JWTClaims> & { scope?: string }>,
  ): Promise<string> {
    return buildIdToken(
      args,
      {
        issuer: this.issuer,
        jwsKey: this.activePrivateIDKey,
        signOptions: this.cfg.idToken?.signOptions,
      },
      cb,
    );
  }

  // OIDC: Verify (introspect) ID Token
  async introspectIdToken(token: string) {
    try {
      const { payload } = await verify<OIDCIdTokenClaims>(
        token,
        this.activePrivateIDKey,
        { issuer: this.issuer, ...this.cfg.idToken?.verifyOptions },
      );
      return { active: true as const, claims: payload };
    } catch {
      return { active: false as const, claims: undefined };
    }
  }

  /**
   * Minimal discovery document suitable for .well-known/openid-configuration.
   */
  override getDiscoveryDocument(
    options?: Omit<OIDCDiscoveryOptions, "issuer">,
  ) {
    return buildDiscoveryDocument({
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
