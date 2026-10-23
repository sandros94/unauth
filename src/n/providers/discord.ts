import { defineOAuth2Provider } from "../flow/oauth2.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import { isRecord } from "../flow/_internal/http/shared.ts";
import type { WebRequestEvent } from "../request-event.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
  nonEmpty,
  userinfoAs,
} from "./_internal/shared.ts";

/** `GET /users/@me` (https://discord.com/developers/docs/resources/user#user-object). */
export interface DiscordProfile {
  /** A snowflake. */
  id: string;
  username: string;
  /** `"0"` for accounts on the unique-username system. */
  discriminator: string;
  global_name: string | null;
  /** Avatar hash; `a_`-prefixed when animated. */
  avatar: string | null;
  /** With the `email` scope. */
  email?: string | null;
  verified?: boolean;
  locale?: string;
  mfa_enabled?: boolean;
  banner?: string | null;
  accent_color?: number | null;
  premium_type?: number;
  public_flags?: number;
  flags?: number;
  bot?: boolean;
}

/** Options of {@link defineDiscordProvider}. */
export interface DiscordProviderConfig extends PresetConfig {
  clientSecret: string;
}

/**
 * Discord: authorization `https://discord.com/oauth2/authorize`, token
 * `https://discord.com/api/oauth2/token`, account from `GET https://discord.com/api/users/@me`.
 * PKCE `S256`; the client secret in the request body. `avatar` is the user's avatar on Discord's
 * CDN, else the default avatar Discord assigns
 * (https://discord.com/developers/docs/reference#image-formatting).
 *
 * @default scopes `["identify", "email"]`
 */
export function defineDiscordProvider(
  options: DiscordProviderConfig,
): OAuthProvider<DiscordProfile> {
  return defineOAuth2Provider({
    id: options.id ?? "discord",
    label: options.label ?? "Discord",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: "https://discord.com/oauth2/authorize",
    token: "https://discord.com/api/oauth2/token",
    userinfo: "https://discord.com/api/users/@me",
    tokenAuth: "body",
    scopes: options.scopes ?? ["identify", "email"],
    authorizationParams: options.authorizationParams,
    profile: discordProfile,
  });
}

/** Options of {@link defineDiscordHandler}: {@link DiscordProviderConfig} and `defineSignInHandler`'s, in one object. */
export type DiscordHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<DiscordProviderConfig, DiscordProfile, TResult, TEvent, TLink>;

/**
 * Both legs of a Discord sign-in on one route: `defineSignInHandler` on {@link defineDiscordProvider}, the
 * options split between them by the provider's keys.
 */
export const defineDiscordHandler: PresetHandler<DiscordProviderConfig, DiscordProfile> =
  /* @__PURE__ */ presetHandler(defineDiscordProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function discordProfile(context: ProfileContext): ProfileResult<DiscordProfile> {
  const user = userinfoAs(context, isDiscordProfile, { provider: "Discord" });
  const result: ProfileResult<DiscordProfile> = {
    subject: user.id,
    profile: user,
    name: nonEmpty(user.global_name) ?? user.username,
    avatar: discordAvatar(user),
  };
  const email = nonEmpty(user.email);
  if (email !== undefined) {
    result.email = email;
    if (typeof user.verified === "boolean") result.emailVerified = user.verified;
  }
  return result;
}

/** The CDN URL of the user's avatar, else of the default one Discord assigns. */
export function discordAvatar(
  user: Pick<DiscordProfile, "id" | "avatar" | "discriminator">,
): string {
  const cdn = "https://cdn.discordapp.com";
  if (user.avatar) {
    const format = user.avatar.startsWith("a_") ? "gif" : "png";
    return `${cdn}/avatars/${user.id}/${user.avatar}.${format}`;
  }
  const index =
    user.discriminator === "0" || !user.discriminator
      ? Number((BigInt(user.id) >> 22n) % 6n)
      : Number(user.discriminator) % 5;
  return `${cdn}/embed/avatars/${index}.png`;
}

function isDiscordProfile(value: unknown): value is DiscordProfile {
  return (
    isRecord(value) &&
    typeof value.id === "string" &&
    /^\d+$/.test(value.id) &&
    typeof value.username === "string"
  );
}
