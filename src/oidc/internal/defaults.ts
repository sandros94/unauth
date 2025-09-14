import type {
  AccessTokenOptions,
  ResolvedAccessTokenOptions,
  OAuthOptions,
  ResolvedOAuthOptions,
} from "../../oauth/internal/defaults";
import {
  accessTokenDefaults,
  oauthOptionsDefaults,
} from "../../oauth/internal/defaults";

import type { OIDCProviderHooks } from "../hooks";

export type IDTokenOptions = AccessTokenOptions;

export type ResolvedIDTokenOptions = ResolvedAccessTokenOptions;

export interface OIDCOptions extends OAuthOptions {
  idToken: IDTokenOptions;
}

export interface ResolvedOIDCOptions
  extends Omit<ResolvedOAuthOptions, "hooks"> {
  hooks: OIDCProviderHooks;
  idToken: ResolvedIDTokenOptions;
}

export function idTokenDefaults<T extends IDTokenOptions>(
  opts: T,
): ResolvedIDTokenOptions {
  // Since they share the same structure, we can reuse the access token defaults
  return accessTokenDefaults(opts);
}

export function oidcOptionsDefaults<T extends OIDCOptions>(
  opts: T,
): ResolvedOIDCOptions {
  return {
    ...oauthOptionsDefaults(opts),
    idToken: idTokenDefaults(opts.idToken),
  };
}
