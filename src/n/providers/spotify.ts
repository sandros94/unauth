import { defineOAuth2Provider } from "../flow/oauth2.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import type { WebRequestEvent } from "../request-event.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
  hasMember,
  nonEmpty,
  userinfoAs,
} from "./_internal/shared.ts";

/** `GET /v1/me` (https://developer.spotify.com/documentation/web-api/reference/get-current-users-profile). */
export interface SpotifyProfile {
  id: string;
  display_name: string | null;
  /** With `user-read-email`; Spotify documents it as unverified. */
  email?: string;
  images?: { url: string; height: number | null; width: number | null }[];
  /** With `user-read-private`. */
  country?: string;
  /** With `user-read-private`. */
  product?: string;
  uri: string;
  href: string;
  external_urls: { spotify: string };
  followers?: { href: string | null; total: number };
  explicit_content?: { filter_enabled: boolean; filter_locked: boolean };
  type: "user";
}

/** Options of {@link defineSpotifyProvider}. */
export interface SpotifyProviderConfig extends PresetConfig {
  /** Confidential clients authenticate with HTTP Basic; public clients leave it out and use PKCE. */
  clientSecret?: string;
}

/**
 * Spotify: authorization `https://accounts.spotify.com/authorize`, token
 * `https://accounts.spotify.com/api/token`, account from `GET https://api.spotify.com/v1/me`.
 * With a client secret, HTTP Basic and no PKCE; without one, a public client with PKCE `S256`
 * (https://developer.spotify.com/documentation/web-api/tutorials/code-pkce-flow). Spotify
 * documents `email` as unverified: `emailVerified` stays unset.
 *
 * @default scopes `["user-read-email", "user-read-private"]`
 */
export function defineSpotifyProvider(
  options: SpotifyProviderConfig,
): OAuthProvider<SpotifyProfile> {
  const confidential = Boolean(options.clientSecret);
  return defineOAuth2Provider({
    id: options.id ?? "spotify",
    label: options.label ?? "Spotify",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: "https://accounts.spotify.com/authorize",
    token: "https://accounts.spotify.com/api/token",
    userinfo: "https://api.spotify.com/v1/me",
    tokenAuth: confidential ? "basic" : "none",
    pkce: confidential ? false : "S256",
    scopes: options.scopes ?? ["user-read-email", "user-read-private"],
    authorizationParams: options.authorizationParams,
    profile: spotifyProfile,
  });
}

/** Options of {@link defineSpotifyHandler}: {@link SpotifyProviderConfig} and `defineSignInHandler`'s, in one object. */
export type SpotifyHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
> = PresetHandlerConfig<SpotifyProviderConfig, SpotifyProfile, TResult, TEvent, TMemo>;

/**
 * Both legs of a Spotify sign-in on one route: `defineSignInHandler` on {@link defineSpotifyProvider}, the
 * options split between them by the provider's keys.
 */
export const defineSpotifyHandler: PresetHandler<SpotifyProviderConfig, SpotifyProfile> =
  /* @__PURE__ */ presetHandler(defineSpotifyProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function spotifyProfile(context: ProfileContext): ProfileResult<SpotifyProfile> {
  const user = userinfoAs(context, isSpotifyProfile, { provider: "Spotify" });
  const result: ProfileResult<SpotifyProfile> = { subject: user.id, profile: user };
  const name = nonEmpty(user.display_name);
  if (name !== undefined) result.name = name;
  const avatar = Array.isArray(user.images) ? nonEmpty(user.images[0]?.url) : undefined;
  if (avatar !== undefined) result.avatar = avatar;
  const email = nonEmpty(user.email);
  if (email !== undefined) result.email = email;
  return result;
}

function isSpotifyProfile(value: unknown): value is SpotifyProfile {
  return hasMember(value, "id", "string");
}
