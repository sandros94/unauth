import type { JWK, JWTClaims } from "unjwt";

/**
 * Configuration for the OIDCProvider class.
 */
export interface OIDCProviderConfig {
  /**
   * The Issuer Identifier URL for the provider.
   * This is a REQUIRED value in the ID Token.
   */
  issuer: string;
  /**
   * An array of private keys in JWK format used for signing tokens.
   */
  privateKeys: JWK[];
  /**
   * An array of public keys in JWK format used for verifying tokens.
   */
  publicKeys: JWK[];
}

/**
 * Standard claims for an OpenID Connect UserInfo response.
 */
export interface UserInfoClaims extends JWTClaims {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  middle_name?: string;
  nickname?: string;
  preferred_username?: string;
  profile?: string;
  picture?: string;
  website?: string;
  email?: string;
  email_verified?: boolean;
  gender?: string;
  birthdate?: string;
  zoneinfo?: string;
  locale?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  address?: object;
  updated_at?: number;
}

/**
 * Standard and custom claims for an OpenID Connect ID Token.
 */
export interface IdTokenClaims extends UserInfoClaims {
  // Standard OIDC claims from Section 2 of the spec
  acr?: string;
  amr?: string[];
  azp?: string;
  auth_time?: number;
  nonce?: string;
}
