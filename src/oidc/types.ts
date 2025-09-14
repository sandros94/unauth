import type { JWTClaims } from "unjwt";

export interface IdTokenClaims extends JWTClaims {
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
