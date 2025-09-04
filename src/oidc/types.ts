import type { JWTClaims, JWK, JWSSignOptions } from "unjwt";

export interface OIDCIdTokenClaims extends JWTClaims {
  iss: Exclude<JWTClaims["iss"], undefined>;
  sub: string;
  aud: string | string[];
  exp: Exclude<JWTClaims["exp"], undefined>;
  iat: Exclude<JWTClaims["iat"], undefined>;
  auth_time?: number;
  nonce?: string;
  acr?: string;
  amr?: string[];
  azp?: string;
  at_hash?: string;
  c_hash?: string;
  sid?: string;
}

export interface OIDCIdTokenOptions {
  issuer: string;
  jwsKey: JWK;
  signOptions?: JWSSignOptions;
  /**
   * For EdDSA algorithms, specify which hash to use for at_hash/c_hash computation.
   * Default is "SHA-256". For HS/RS/ES/PS alg families the hash is derived from alg bit length.
   */
  eddsaHashAlgorithm?: "SHA-256" | "SHA-384" | "SHA-512";
}

export interface OIDCBuildIdTokenArgs {
  subject: string;
  audience: string | string[];
  nonce?: string;
  auth_time?: number | Date;
  acr?: string;
  amr?: string[];
  azp?: string;
  /** When provided, an at_hash will be computed according to the JWS alg */
  access_token?: string;
  /** When provided, a c_hash will be computed according to the JWS alg (hybrid flows) */
  code?: string;
  /** Optional extra claims to merge into the ID Token */
  additionalClaims?: Partial<JWTClaims>;
}

export interface OIDCUserInfoProfile extends JWTClaims {
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
  address?: Record<string, unknown>;
  updated_at?: number;
}
