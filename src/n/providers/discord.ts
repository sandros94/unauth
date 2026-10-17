import { oauth2 } from "../flow/oauth2.ts";
import type { ProfileContext, ProfileResult, Provider } from "../flow/types.ts";
import { isRecord } from "../flow/_http.ts";
import { type PresetOptions, nonEmpty, userinfoAs } from "./_shared.ts";

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
export interface DiscordProviderOptions extends PresetOptions {
  clientSecret: string;
}

/**
 * Discord. `avatar` is built on Discord's CDN, falling back to the default avatar Discord shows
 * (https://discord.com/developers/docs/reference#image-formatting).
 * @default scopes `["identify", "email"]`
 */
export function defineDiscordProvider(options: DiscordProviderOptions): Provider<DiscordProfile> {
  return oauth2({
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
