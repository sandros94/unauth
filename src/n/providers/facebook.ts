import { isRecord } from "../flow/_internal/http/shared.ts";
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

/** Graph API `GET /me` with the requested `fields` (https://developers.facebook.com/docs/graph-api/reference/user). */
export interface FacebookProfile {
  id: string;
  name?: string;
  first_name?: string;
  last_name?: string;
  /** Only when the user has a valid address and granted `email`. */
  email?: string;
  picture?: { data: { url: string; width?: number; height?: number; is_silhouette?: boolean } };
}

/** Options of {@link defineFacebookProvider}. */
export interface FacebookProviderConfig extends PresetConfig {
  clientSecret: string;
  /** Graph API version; versions expire about two years after release. @default "v26.0" */
  version?: string;
  /** `GET /me` fields. @default ["id", "name", "email", "picture"] */
  fields?: string[];
}

/**
 * Facebook Login: authorization `https://www.facebook.com/<version>/dialog/oauth`, token
 * `https://graph.facebook.com/<version>/oauth/access_token`, account from Graph API `GET /me` with
 * the token in the `Authorization` header, never in the URL. PKCE `S256`; the client secret in the
 * request body; scopes comma-separated. Facebook does not say whether `email` is verified:
 * `emailVerified` stays unset.
 *
 * @default scopes `["email", "public_profile"]`
 */
export function defineFacebookProvider(
  options: FacebookProviderConfig,
): OAuthProvider<FacebookProfile> {
  const version = options.version ?? "v26.0";
  const fields = (options.fields ?? ["id", "name", "email", "picture"]).join(",");
  return defineOAuth2Provider({
    id: options.id ?? "facebook",
    label: options.label ?? "Facebook",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: `https://www.facebook.com/${version}/dialog/oauth`,
    token: `https://graph.facebook.com/${version}/oauth/access_token`,
    userinfo: `https://graph.facebook.com/${version}/me?fields=${encodeURIComponent(fields)}`,
    tokenAuth: "body",
    scopes: options.scopes ?? ["email", "public_profile"],
    scopeSeparator: ",",
    authorizationParams: options.authorizationParams,
    profile: facebookProfile,
  });
}

/** Options of {@link defineFacebookHandler}: {@link FacebookProviderConfig} and `defineSignInHandler`'s, in one object. */
export type FacebookHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<FacebookProviderConfig, FacebookProfile, TResult, TEvent, TLink>;

/**
 * Both legs of a Facebook sign-in on one route: `defineSignInHandler` on {@link defineFacebookProvider}, the
 * options split between them by the provider's keys.
 */
export const defineFacebookHandler: PresetHandler<FacebookProviderConfig, FacebookProfile> =
  /* @__PURE__ */ presetHandler(defineFacebookProvider, {
    keys: [
      "clientId",
      "clientSecret",
      "version",
      "fields",
      "scopes",
      "authorizationParams",
      "id",
      "label",
    ],
  });

function facebookProfile(context: ProfileContext): ProfileResult<FacebookProfile> {
  const user = userinfoAs(context, isFacebookProfile, { provider: "Facebook" });
  const result: ProfileResult<FacebookProfile> = { subject: user.id, profile: user };
  const name = nonEmpty(user.name);
  if (name !== undefined) result.name = name;
  const email = nonEmpty(user.email);
  if (email !== undefined) result.email = email;
  const picture =
    isRecord(user.picture) && isRecord(user.picture.data) ? user.picture.data.url : undefined;
  const avatar = nonEmpty(picture);
  if (avatar !== undefined) result.avatar = avatar;
  return result;
}

function isFacebookProfile(value: unknown): value is FacebookProfile {
  return hasMember(value, "id", "string");
}
