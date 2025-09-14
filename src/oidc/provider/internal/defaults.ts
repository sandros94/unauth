import {
  type AccessTokenOptions,
  type ResolvedAccessTokenOptions,
  accessTokenDefaults,
} from "../../../oauth/provider/internal";

export * from "../../../oauth/provider/internal/defaults";

export type IdTokenOptions = AccessTokenOptions;

export type ResolvedIdTokenOptions = ResolvedAccessTokenOptions;

export function idTokenDefaults<T extends IdTokenOptions>(
  opts: T,
): ResolvedIdTokenOptions {
  // Since they share the same structure, we can simply reuse the access token defaults
  return accessTokenDefaults(opts);
}
