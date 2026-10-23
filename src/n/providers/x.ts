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

/** `GET /2/users/me` `data` (https://docs.x.com/x-api/users/user-lookup-me). */
export interface XProfile {
  id: string;
  name: string;
  username: string;
  profile_image_url?: string;
  description?: string;
  verified?: boolean;
  verified_type?: string;
  created_at?: string;
}

/** Options of {@link defineXProvider}. */
export interface XProviderOptions extends PresetConfig {
  /** Confidential clients authenticate with HTTP Basic; public clients leave it out. */
  clientSecret?: string;
}

/**
 * X (formerly Twitter) OAuth 2.0, which requires PKCE. The API exposes no email here, so
 * `email` stays unset. @default scopes `["users.read", "tweet.read"]` (X requires `tweet.read`
 * alongside `users.read`)
 */
export function defineXProvider(options: XProviderOptions): OAuthProvider<XProfile> {
  const fields = "profile_image_url,description,verified,verified_type,created_at";
  return defineOAuth2Provider({
    id: options.id ?? "x",
    label: options.label ?? "X",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: "https://x.com/i/oauth2/authorize",
    token: "https://api.x.com/2/oauth2/token",
    userinfo: `https://api.x.com/2/users/me?user.fields=${fields}`,
    tokenAuth: options.clientSecret ? "basic" : "none",
    scopes: options.scopes ?? ["users.read", "tweet.read"],
    authorizationParams: options.authorizationParams,
    profile: xProfile,
  });
}

/** Options of {@link defineXHandler}: {@link XProviderOptions} and `defineSignInHandler`'s, in one object. */
export type XHandlerConfig<
  TSession extends object = AuthSessionData,
  TResult = never,
  TEvent extends HandlerEvent = HandlerEvent,
> = PresetHandlerConfig<XProviderOptions, XProfile, TSession, TResult, TEvent>;

/**
 * Both legs of a X sign-in on one route: `defineSignInHandler` on {@link defineXProvider}, the
 * options split between them by the provider's keys.
 */
export const defineXHandler: PresetHandler<XProviderOptions, XProfile> =
  /* @__PURE__ */ presetHandler(defineXProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function xProfile(context: ProfileContext): ProfileResult<XProfile> {
  const { data } = userinfoAs(context, isUsersMe, { provider: "X" });
  const user = userinfoAs({ ...context, userinfo: data }, isXProfile, { provider: "X" });
  const result: ProfileResult<XProfile> = {
    subject: user.id,
    profile: user,
    name: nonEmpty(user.name) ?? user.username,
  };
  const avatar = nonEmpty(user.profile_image_url);
  if (avatar !== undefined) result.avatar = avatar;
  return result;
}

function isUsersMe(value: unknown): value is { data: Record<string, unknown> } {
  return isRecord(value) && isRecord(value.data);
}

function isXProfile(value: unknown): value is XProfile {
  return hasMember(value, "id", "string") && hasMember(value, "username", "string");
}
