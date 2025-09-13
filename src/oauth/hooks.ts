import type { JWTClaims } from "unjwt";

import type { MaybePromise, ParseType } from "../types";

import type {
  AuthorizationCodeClaims,
  AccessTokenClaims,
  RefreshTokenClaims,
} from "./types";
import type {
  ResolvedOAuthOptions,
  AuthorizationCodeRequest,
  TokenRequest,
} from "./internal";

export type OnAuthorizationCodeReqReturn = AuthorizationCodeRequest & {
  claims: ParseType<JWTClaims & { sub: string }>;
};

/**
 * Lifecycle hooks aimed at persistence / audit / revocation tracking.
 * Configure once on the provider (long–lived).
 */
export interface OAuthProviderHooks {
  onAuthorizeRequest(
    opts: Pick<ResolvedOAuthOptions, "issuer" | "defaultCodeChallengeMethod">,
  ): MaybePromise<OnAuthorizationCodeReqReturn>;
  onAuthorizationCodeIssued?(ctx: {
    claims: AuthorizationCodeClaims;
  }): MaybePromise<void>;
  onAuthorizationCodeCheck?(ctx: {
    claims: AuthorizationCodeClaims;
  }): MaybePromise<void>;
  onAuthorizationCodeUsed?(
    ctx: {
      claims: AuthorizationCodeClaims;
    },
    issued: {
      atClaims: AccessTokenClaims;
      rtClaims: RefreshTokenClaims;
    },
  ): MaybePromise<void>;

  onTokenRequest(): MaybePromise<TokenRequest>;
  onRefreshTokenCheck?(ctx: { claims: RefreshTokenClaims }): MaybePromise<void>;
  onRefreshTokenUsed?(
    ctx: {
      claims: RefreshTokenClaims;
    },
    issued: {
      atClaims: AccessTokenClaims;
      rtClaims: RefreshTokenClaims;
    },
  ): MaybePromise<void>;

  onClientAuthenticate?(ctx: { scope?: string }): MaybePromise<
    JWTClaims & {
      client_id: string;
      scope?: string;
      resource?: string | string[];
    }
  >;
  onClientAuthenticated?(ctx: {
    claims: AccessTokenClaims;
  }): MaybePromise<void>;
}

/**
 * @deprecated
 */
export interface OAuthRequestEvents {
  /** For server wrappers to stash freshly minted tokens / claims. */
  onTokens?(params: {
    access_token: string;
    refresh_token?: string;
    accessTokenClaims: AccessTokenClaims;
    refreshTokenClaims?: RefreshTokenClaims;
  }): void | Promise<void>;
  /** For server wrappers to cache introspection results. */
  onTokenIntrospected?(params: {
    kind: "access" | "refresh";
    token: string;
    claims?: JWTClaims;
  }): void | Promise<void>;
  /** For server wrappers to capture revocation events (in addition to global hook). */
  onRevoked?(params: {
    kind: "access" | "refresh" | "code";
    jti: string;
    iat: number;
    exp: number;
  }): void | Promise<void>;
}
