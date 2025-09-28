import type { JWTClaims } from "unjwt";

import type {
  AuthorizeErrorResponse,
  TokenErrorResponse,
} from "./provider/error";

export type * from "./provider/error";

// #region OAuth token claims

/**
 * Authorization Code JWT Claims, inside a JWE token.
 */
export interface AuthorizationCodeClaims extends RefreshTokenClaims {
  /** The PKCE code challenge corresponding to the verifier. */
  code_challenge: string;
  /** The PKCE method used for the challenge. */
  code_challenge_method?: "plain" | "S256";
  /** The redirect URI used in the authorization request, if any. */
  redirect_uri?: string;
}

/**
 * Access Token JWT Claims, inside a JWS token.
 */
export interface AccessTokenClaims extends JWTClaims {
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
  /** Audience (resource indicators) per RFC 9068. */
  aud: Exclude<JWTClaims["aud"], undefined>;
  /** The scope of the access request. */
  scope?: string;
}

/**
 * Refresh Token JWT Claims, inside a JWE token.
 */
export interface RefreshTokenClaims extends JWTClaims {
  /** The client identifier (client_id) from either public and confidential clients. */
  sub: string;
  /** The client application identifier to which the token is bound. */
  client_id: string;
  /** The issuer identifier. */
  iss: Exclude<JWTClaims["iss"], undefined>;
  /** The issued at time. */
  iat: Exclude<JWTClaims["iat"], undefined>;
  /** The expiration time. */
  exp: Exclude<JWTClaims["exp"], undefined>;
  /** The unique identifier for the token. */
  jti: Exclude<JWTClaims["jti"], undefined>;
  /** Resource Indicators per RFC 8707 as captured during the grant. */
  resource: string | string[];
  /** The scope of the access request. */
  scope?: string;
}

// #endregion OAuth token claims

// #region OAuth request/response types

export interface AuthorizeRequest {
  /** The client application identifier to which the token is bound. */
  client_id: string;
  /**
   * only "code" is supported, implicit removed by OAuth 2.1.
   */
  response_type: "code";
  /**
   * The code challenge for PKCE.
   */
  code_challenge: string;
  /**
   * The code challenge method for PKCE.
   * Must be either "S256" or "plain".
   *
   */
  code_challenge_method?: "S256" | "plain";
  /**
   * If multiple redirect_uris are registered for the client, the original request must contain a valid redirect_uri. Otherwise, if only one is registered it can be used as the default one.
   * If request contains a redirect_uri, it must be validated via exact match against the registered URIs.
   */
  redirect_uri: string;
  /**
   * An opaque value used by the client to maintain state between the request and callback. The authorization server includes this value when redirecting the user agent back to the client.
   */
  state?: string;
  /**
   * The requested scope, space-delimited.
   */
  scope?: string;
  /**
   * Resource Indicators (RFC 8707). Can be provided multiple times or as a space-delimited list by clients; here we accept string or array.
   * These will be mapped to the Access Token audience (aud) during token issuance.
   */
  resource: string | string[];

  [key: string]: unknown;
}

export interface AuthorizeSuccessResponse {
  /**
   * The authorization code (JWE) to be returned to the client.
   */
  code: string;
  /**
   * The identifier of the authorization server which the client can use to prevent mix-up attacks, if the client interacts with more than one authorization server.
   */
  iss: string;
  /**
   * An opaque value used by the client to maintain state between the request and callback. The authorization server includes this value when redirecting the user agent back to the client.
   */
  state?: string;
}

export type AuthorizeResponse =
  | AuthorizeSuccessResponse
  | AuthorizeErrorResponse;

export interface AuthorizationCodeGrantRequest {
  grant_type: "authorization_code";
  /** The authorization code received from the authorization server. */
  code: string;
  /** The client identifier. REQUIRED for public clients. */
  client_id: string;
  /**
   * The PKCE code verifier. REQUIRED if `code_challenge` was used in the
   * authorization request, which is mandatory in OAuth 2.1.
   */
  code_verifier: string;
}

export interface ClientCredentialsGrantRequest {
  grant_type: "client_credentials";
  /** The confidential client identifier, used as subject of the generated token. */
  client_id: string;
  /** Resource Indicators per RFC 8707. */
  resource: string | string[];
  /** The requested scope, limited to the client's own permissions. */
  scope?: string;
}

export interface RefreshTokenGrantRequest {
  grant_type: "refresh_token";
  /** The refresh token issued to the client. */
  refresh_token: string;
  /** The client identifier, used for binding validation. */
  client_id: string;
  /**
   * The scope of the access request. MUST NOT include any scope not
   * originally granted. If omitted, the original scope is used.
   */
  scope?: string;
}

/**
 * Represents a token request from a client to the token endpoint.
 * This is a discriminated union based on the `grant_type`.
 */
export type TokenRequest =
  | AuthorizationCodeGrantRequest
  | ClientCredentialsGrantRequest
  | RefreshTokenGrantRequest;

/**
 * Represents a successful response from the token endpoint.
 */
export interface TokenSuccessResponse {
  /** The access token. */
  access_token: string;
  /** The type of token (case-insensitive). MUST be "Bearer" for this implementation. */
  token_type: "Bearer";
  /** The lifetime in seconds of the access token. */
  expires_in: number;
  /** The scope of the access token issued. */
  scope?: string;
  /** A new refresh token (optional, e.g., for rotation). */
  refresh_token?: string;
}

export type TokenResponse = TokenSuccessResponse | TokenErrorResponse;
