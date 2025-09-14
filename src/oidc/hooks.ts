import type { OAuthProviderHooks } from "../oauth";
import type { AccessTokenClaims, RefreshTokenClaims } from "../oauth/types";
import type { IdTokenClaims } from "./types";

import type { MaybePromise } from "../types";

export interface OnIdTokenContextBase {
  /** Base access token claims used to derive id_token (iss, sub, client_id). */
  accessToken: AccessTokenClaims;
  /** Optional refresh token claims if grant was refresh_token. */
  refreshToken?: RefreshTokenClaims;
  /** Optional nonce captured during authorization. */
  nonce?: string;
}

export type OnIdTokenContext =
  | ({ reason: "authorization_code" } & OnIdTokenContextBase)
  | ({ reason: "refresh_token" } & OnIdTokenContextBase);

/**
 * OIDC provider hooks extend the OAuth ones with ID Token customization.
 */
export interface OIDCProviderHooks extends OAuthProviderHooks {
  /**
   * Customize or extend ID Token claims before signing. Return partials to merge.
   */
  onIdTokenClaims?(ctx: OnIdTokenContext): MaybePromise<Partial<IdTokenClaims>>;
}
