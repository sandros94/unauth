import type { JWK, JWTClaims } from "unjwt";

export interface OAuthServerConfig {
  issuer: string;
  privateKey: JWK;
  publicKey: JWK;
  accessTokenLifetime?: number; // Default: 3600
  refreshTokenLifetime?: number; // Default: 1209600 (30 days)
  authorizationCodeLifetime?: number; // Default: 600
  scopes?: {
    available?: string[];
    default?: string[];
  };
  jweSecret?: string | JWK;
}

export interface OAuthRefreshTokenClaims extends JWTClaims {
  /**
   * The client identifier (client_id) from either public and confidential clients.
   */
  sub: string;
  /**
   * The issuer identifier.
   */
  iss: Exclude<JWTClaims["iss"], undefined>;
  /**
   * The issued at time.
   */
  iat: Exclude<JWTClaims["iat"], undefined>;
  /**
   * The expiration time.
   */
  exp: Exclude<JWTClaims["exp"], undefined>;
  /**
   * The unique identifier for the token.
   */
  jti: Exclude<JWTClaims["jti"], undefined>;
  /**
   * The scope of the access request.
   */
  scope?: string;
}

export interface OAuthAuthorizationCodeClaims extends OAuthRefreshTokenClaims {
  /**
   * The hash of the code verifier.
   */
  code_challenge: string;
  /**
   * The method used to hash the code verifier.
   * @default "plain"
   */
  code_challenge_method?: "plain" | "S256";
  /**
   * The scope of the access request.
   */
  scope?: string;
}

export * from "./token";
export * from "./authorize";
