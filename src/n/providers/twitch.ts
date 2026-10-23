import { isRecord } from "../flow/_http.ts";
import { defineOAuth2Provider } from "../flow/oauth2.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import type { AuthSessionData } from "../_session-data.ts";
import type { HandlerEvent } from "../handler.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
  hasMember,
  nonEmpty,
  userinfoAs,
} from "./_shared.ts";

/** An entry of Helix `GET /users` (https://dev.twitch.tv/docs/api/reference/#get-users). */
export interface TwitchProfile {
  id: string;
  login: string;
  display_name: string;
  type: string;
  broadcaster_type: string;
  description: string;
  profile_image_url: string;
  offline_image_url: string;
  /** Verified address; with `user:read:email`. */
  email?: string;
  created_at: string;
}

/** Options of {@link defineTwitchProvider}. */
export interface TwitchProviderConfig extends PresetConfig {
  clientSecret: string;
}

/**
 * Twitch, reading the account from Helix, which wants the `Client-Id` header and answers
 * `{ data: [user] }`. Twitch documents `email` as the verified address, so `emailVerified` is
 * `true` when it is present. No PKCE: Twitch's authorization-code flow documents none
 * (https://dev.twitch.tv/docs/authentication/getting-tokens-oauth/). @default scopes
 * `["user:read:email"]`
 */
export function defineTwitchProvider(options: TwitchProviderConfig): OAuthProvider<TwitchProfile> {
  return defineOAuth2Provider({
    id: options.id ?? "twitch",
    label: options.label ?? "Twitch",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: "https://id.twitch.tv/oauth2/authorize",
    token: "https://id.twitch.tv/oauth2/token",
    userinfo: "https://api.twitch.tv/helix/users",
    userinfoHeaders: { "client-id": options.clientId },
    tokenAuth: "body",
    // Twitch documents no PKCE parameters; `state` and the confidential client protect the flow.
    pkce: false,
    scopes: options.scopes ?? ["user:read:email"],
    authorizationParams: options.authorizationParams,
    profile: twitchProfile,
  });
}

/** Options of {@link defineTwitchHandler}: {@link TwitchProviderConfig} and `defineSignInHandler`'s, in one object. */
export type TwitchHandlerConfig<
  TSession extends object = AuthSessionData,
  TResult = never,
  TEvent extends HandlerEvent = HandlerEvent,
> = PresetHandlerConfig<TwitchProviderConfig, TwitchProfile, TSession, TResult, TEvent>;

/**
 * Both legs of a Twitch sign-in on one route: `defineSignInHandler` on {@link defineTwitchProvider}, the
 * options split between them by the provider's keys.
 */
export const defineTwitchHandler: PresetHandler<TwitchProviderConfig, TwitchProfile> =
  /* @__PURE__ */ presetHandler(defineTwitchProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function twitchProfile(context: ProfileContext): ProfileResult<TwitchProfile> {
  const { data } = userinfoAs(context, isHelixUsers, { provider: "Twitch" });
  const user = userinfoAs({ ...context, userinfo: data[0] }, isTwitchProfile, {
    provider: "Twitch",
  });
  const result: ProfileResult<TwitchProfile> = {
    subject: user.id,
    profile: user,
    name: nonEmpty(user.display_name) ?? user.login,
  };
  const avatar = nonEmpty(user.profile_image_url);
  if (avatar !== undefined) result.avatar = avatar;
  const email = nonEmpty(user.email);
  if (email !== undefined) {
    result.email = email;
    result.emailVerified = true;
  }
  return result;
}

function isHelixUsers(value: unknown): value is { data: Record<string, unknown>[] } {
  return isRecord(value) && Array.isArray(value.data);
}

function isTwitchProfile(value: unknown): value is TwitchProfile {
  return hasMember(value, "id", "string") && hasMember(value, "login", "string");
}
