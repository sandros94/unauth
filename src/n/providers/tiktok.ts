import { isRecord, profileError } from "../flow/_internal/http/shared.ts";
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

/** `data.user` of `GET /v2/user/info/` (https://developers.tiktok.com/doc/tiktok-api-v2-get-user-info). */
export interface TikTokProfile {
  open_id: string;
  /** The same user across the developer's apps. */
  union_id?: string;
  avatar_url?: string;
  avatar_url_100?: string;
  avatar_large_url?: string;
  display_name?: string;
}

/** Options of {@link defineTikTokProvider}. */
export interface TikTokProviderConfig extends PresetConfig {
  /** The app's client key, which TikTok names `client_key`. */
  clientId: string;
  clientSecret: string;
}

const FIELDS = "open_id,union_id,avatar_url,avatar_url_100,avatar_large_url,display_name";

/**
 * TikTok Login Kit for Web: authorization `https://www.tiktok.com/v2/auth/authorize/`, token
 * `https://open.tiktokapis.com/v2/oauth/token/`, account from
 * `GET https://open.tiktokapis.com/v2/user/info/`. The client identifier travels as `client_key`;
 * no PKCE, absent from the web flow
 * (https://developers.tiktok.com/doc/login-kit-web); the client secret in the request body;
 * scopes comma-separated. The user is unwrapped from `data.user`, and an `error.code` other than
 * `"ok"` is refused. TikTok exposes no email: `email` stays unset.
 *
 * @default scopes `["user.info.basic"]`
 */
export function defineTikTokProvider(options: TikTokProviderConfig): OAuthProvider<TikTokProfile> {
  return defineOAuth2Provider({
    id: options.id ?? "tiktok",
    label: options.label ?? "TikTok",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    clientIdParameter: "client_key",
    authorization: "https://www.tiktok.com/v2/auth/authorize/",
    token: "https://open.tiktokapis.com/v2/oauth/token/",
    userinfo: `https://open.tiktokapis.com/v2/user/info/?fields=${FIELDS}`,
    tokenAuth: "body",
    pkce: false,
    scopes: options.scopes ?? ["user.info.basic"],
    scopeSeparator: ",",
    authorizationParams: options.authorizationParams,
    profile: tiktokProfile,
  });
}

/** Options of {@link defineTikTokHandler}: {@link TikTokProviderConfig} and `defineSignInHandler`'s, in one object. */
export type TikTokHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<TikTokProviderConfig, TikTokProfile, TResult, TEvent, TLink>;

/**
 * Both legs of a TikTok sign-in on one route: `defineSignInHandler` on {@link defineTikTokProvider}, the
 * options split between them by the provider's keys.
 */
export const defineTikTokHandler: PresetHandler<TikTokProviderConfig, TikTokProfile> =
  /* @__PURE__ */ presetHandler(defineTikTokProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function tiktokProfile(context: ProfileContext): ProfileResult<TikTokProfile> {
  const answer = userinfoAs(context, isUserInfo, { provider: "TikTok" });
  const code = isRecord(answer.error) ? answer.error.code : undefined;
  if (code !== undefined && code !== "ok") {
    throw profileError(`TikTok refused the user info request with code ${JSON.stringify(code)}.`);
  }
  const nested = answer.data?.user;
  const user = userinfoAs(
    { ...context, userinfo: isRecord(nested) ? nested : undefined },
    isTikTokProfile,
    { provider: "TikTok" },
  );
  const result: ProfileResult<TikTokProfile> = { subject: user.open_id, profile: user };
  const name = nonEmpty(user.display_name);
  if (name !== undefined) result.name = name;
  const avatar = nonEmpty(user.avatar_url);
  if (avatar !== undefined) result.avatar = avatar;
  return result;
}

function isUserInfo(
  value: unknown,
): value is { data?: { user?: unknown }; error?: Record<string, unknown> } {
  return isRecord(value) && (value.data === undefined || isRecord(value.data));
}

function isTikTokProfile(value: unknown): value is TikTokProfile {
  return hasMember(value, "open_id", "string");
}
