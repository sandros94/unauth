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

/** `GET /api/v1/user` (https://open-api.netlify.com/#tag/user). */
export interface NetlifyProfile {
  id: string;
  uid?: string;
  full_name?: string | null;
  avatar_url?: string | null;
  email?: string | null;
  affiliate_id?: string;
  site_count?: number;
  created_at?: string;
  last_login?: string;
  login_providers?: string[];
}

/** Options of {@link defineNetlifyProvider}. */
export interface NetlifyProviderConfig extends PresetConfig {
  clientSecret: string;
}

/**
 * Netlify: authorization `https://app.netlify.com/authorize`, token
 * `https://api.netlify.com/oauth/token`, account from `GET https://api.netlify.com/api/v1/user`.
 * No PKCE, which Netlify's authorization-code flow does not document
 * (https://docs.netlify.com/api/get-started/); the client secret in the request body. Netlify has no scopes: an authorization grants the whole account, so `scopes` is empty.
 * Each OAuth application registers exactly one redirect URI, compared verbatim. Netlify does not
 * say whether `email` is verified: `emailVerified` stays unset.
 *
 * @default scopes `[]`
 */
export function defineNetlifyProvider(
  options: NetlifyProviderConfig,
): OAuthProvider<NetlifyProfile> {
  return defineOAuth2Provider({
    id: options.id ?? "netlify",
    label: options.label ?? "Netlify",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: "https://app.netlify.com/authorize",
    token: "https://api.netlify.com/oauth/token",
    userinfo: "https://api.netlify.com/api/v1/user",
    tokenAuth: "body",
    pkce: false,
    scopes: options.scopes ?? [],
    authorizationParams: options.authorizationParams,
    profile: netlifyProfile,
  });
}

/** Options of {@link defineNetlifyHandler}: {@link NetlifyProviderConfig} and `defineSignInHandler`'s, in one object. */
export type NetlifyHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
> = PresetHandlerConfig<NetlifyProviderConfig, NetlifyProfile, TResult, TEvent, TMemo>;

/**
 * Both legs of a Netlify sign-in on one route: `defineSignInHandler` on {@link defineNetlifyProvider}, the
 * options split between them by the provider's keys.
 */
export const defineNetlifyHandler: PresetHandler<NetlifyProviderConfig, NetlifyProfile> =
  /* @__PURE__ */ presetHandler(defineNetlifyProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function netlifyProfile(context: ProfileContext): ProfileResult<NetlifyProfile> {
  const user = userinfoAs(context, isNetlifyProfile, { provider: "Netlify" });
  const result: ProfileResult<NetlifyProfile> = { subject: user.id, profile: user };
  const name = nonEmpty(user.full_name);
  if (name !== undefined) result.name = name;
  const avatar = nonEmpty(user.avatar_url);
  if (avatar !== undefined) result.avatar = avatar;
  const email = nonEmpty(user.email);
  if (email !== undefined) result.email = email;
  return result;
}

function isNetlifyProfile(value: unknown): value is NetlifyProfile {
  return hasMember(value, "id", "string");
}
