import {
  type AccessTokenOptions,
  type ResolvedAccessTokenOptions,
  type OAuthProviderOptions,
  accessTokenDefaults,
  oauthProviderDefaults,
} from "../../../oauth/provider/internal";

export * from "../../../oauth/provider/internal/defaults";
import {
  type BuildOIDCDiscoveryArgs,
  buildOIDCDiscoveryDocument,
} from "./discovery";

export type IdTokenOptions = AccessTokenOptions;

export type ResolvedIdTokenOptions = ResolvedAccessTokenOptions;

export function idTokenDefaults<T extends IdTokenOptions>(
  opts: T,
): ResolvedIdTokenOptions {
  // Since they share the same structure, we can simply reuse the access token defaults
  return accessTokenDefaults(opts);
}

export interface OIDCProviderOptions
  extends Omit<OAuthProviderOptions, "discovery"> {
  discovery?: BuildOIDCDiscoveryArgs;
  idTokenOptions: IdTokenOptions;
}

/**
 * Apply all defaults for an OAuthProvider instance.
 */
export function oidcProviderDefaults(args: OIDCProviderOptions) {
  const { idTokenOptions, discovery, ...opts } = args;

  return {
    ...oauthProviderDefaults(opts),
    discovery: buildOIDCDiscoveryDocument({
      ...discovery,
      issuer: args.issuer,
    }),
    idTokenOptions: idTokenDefaults(idTokenOptions),
  };
}
