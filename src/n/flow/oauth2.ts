import { configError } from "./_http.ts";
import { standardProfile } from "./_profile.ts";
import { defineProvider } from "./provider.ts";
import type { ProfileContext, ProfileResult, OAuthProvider, ProviderConfig } from "./types.ts";

/** Maps a provider's account data to an identity. */
export type ProfileMapper<TProfile> = (
  context: ProfileContext,
) => ProfileResult<TProfile> | Promise<ProfileResult<TProfile>>;

/** Options of {@link defineOAuth2Provider}. */
export interface OAuth2ProviderConfig extends Pick<
  ProviderConfig,
  | "label"
  | "scopes"
  | "scopeSeparator"
  | "pkce"
  | "tokenAuth"
  | "responseMode"
  | "authorizationParams"
  | "tokenParams"
  | "userinfoHeaders"
  | "insecureHosts"
> {
  id: string;
  clientId: string;
  clientSecret?: OAuthClientSecret;
  authorization: string;
  token: string;
  userinfo?: string;
}

/** A `client_secret`, or a function minting one for every token request. */
export type OAuthClientSecret = string | (() => string | Promise<string>);

/**
 * A generic OAuth 2.0 provider (authorization code with PKCE). Without `profile`, the account is
 * the userinfo payload read through its standard claims (`sub` or `id`, `name`, `email`…).
 */
export function defineOAuth2Provider(
  options: OAuth2ProviderConfig & { userinfo: string },
): OAuthProvider;
export function defineOAuth2Provider<TProfile>(
  options: OAuth2ProviderConfig & { profile: ProfileMapper<TProfile> },
): OAuthProvider<TProfile>;
export function defineOAuth2Provider(
  options: OAuth2ProviderConfig & { profile?: ProfileMapper<unknown> },
): OAuthProvider<unknown> {
  const { clientId, clientSecret, profile, ...rest } = options;
  if (!profile && !options.userinfo) {
    throw configError(
      `OAuthProvider ${JSON.stringify(options.id)} needs "userinfo" or "profile" to know who signed in.`,
    );
  }
  return defineProvider<unknown>({
    ...rest,
    kind: "oauth2",
    client: { id: clientId, secret: clientSecret },
    profile: profile ?? ((context) => standardProfile(context.userinfo ?? {})),
  });
}
