import type { JWK } from "unjwt";

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
