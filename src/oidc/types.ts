import type { JWTClaims } from "unjwt";

import type {
  AuthorizationCodeClaims as OAuthAuthorizationCodeClaims,
  TokenSuccessResponse as OAuthTokenSuccessResponse,
} from "../oauth/types";

export type * from "../oauth/provider/error";

export type {
  AccessTokenClaims,
  RefreshTokenClaims,
  AuthorizeSuccessResponse,
  AuthorizeResponse,
  AuthorizationCodeGrantRequest,
  ClientCredentialsGrantRequest,
  RefreshTokenGrantRequest,
  TokenRequest,
  TokenResponse,
} from "../oauth/types";

export type { AuthorizeRequest } from "./provider";

export interface IdTokenClaims extends JWTClaims {
  iss: Exclude<JWTClaims["iss"], undefined>;
  sub: string;
  aud: string | string[];
  exp: Exclude<JWTClaims["exp"], undefined>;
  iat: Exclude<JWTClaims["iat"], undefined>;
  at_hash: string;
  nonce?: string;
  auth_time?: number;
  acr?: string;
  amr?: string[];
  azp?: string;
  sid?: string;
}

export interface AuthorizationCodeClaims extends OAuthAuthorizationCodeClaims {
  nonce?: string;
}

export interface TokenSuccessResponse extends OAuthTokenSuccessResponse {
  id_token: string;
}
