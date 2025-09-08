import type { JWTClaims } from "unjwt";

export interface OAuthRefreshTokenClaims extends JWTClaims {
  /** The client identifier (client_id) from either public and confidential clients. */
  sub: string;
  /** The client application identifier to which the token is bound. */
  client_id?: string;
  /** The issuer identifier. */
  iss: Exclude<JWTClaims["iss"], undefined>;
  /** The issued at time. */
  iat: Exclude<JWTClaims["iat"], undefined>;
  /** The expiration time. */
  exp: Exclude<JWTClaims["exp"], undefined>;
  /** The unique identifier for the token. */
  jti: Exclude<JWTClaims["jti"], undefined>;
  /** The scope of the access request. */
  scope?: string;
  /** Resource Indicators per RFC 8707 as captured during the grant. */
  resource?: string | string[];
}

export interface OAuthAuthorizationCodeClaims extends OAuthRefreshTokenClaims {
  /** The PKCE code challenge corresponding to the verifier. */
  code_challenge: string;
  /** The PKCE method used for the challenge. @default "plain" */
  code_challenge_method?: "plain" | "S256";
  /** The scope of the access request. */
  scope?: string;
  /** The redirect URI used in the authorization request, if any. */
  redirect_uri?: string;
  // Note: redirect_uri may be added at runtime; the base JWTClaims is open for additional fields.
}

export interface OAuthAccessTokenClaims extends JWTClaims {
  /** The client identifier (client_id) from either public and confidential clients. */
  sub: string;
  /** The client application identifier (RFC 9068). */
  client_id: string;
  /** The issuer identifier. */
  iss: Exclude<JWTClaims["iss"], undefined>;
  /** The issued at time. */
  iat: Exclude<JWTClaims["iat"], undefined>;
  /** The expiration time. */
  exp: Exclude<JWTClaims["exp"], undefined>;
  /** The unique identifier for the token. */
  jti: Exclude<JWTClaims["jti"], undefined>;
  /** The scope of the access request. */
  scope: string;
  /** Audience (resource indicators) per RFC 9068. */
  aud: Exclude<JWTClaims["aud"], undefined>;
}
