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

/** Microsoft Graph `GET /me` (https://learn.microsoft.com/graph/api/user-get). */
export interface MicrosoftProfile {
  /** The user's object id. */
  id: string;
  displayName: string | null;
  givenName?: string | null;
  surname?: string | null;
  userPrincipalName: string;
  /** The mailbox address; `null` for accounts without one. */
  mail: string | null;
  jobTitle?: string | null;
  mobilePhone?: string | null;
  officeLocation?: string | null;
  preferredLanguage?: string | null;
  businessPhones?: string[];
}

/** Options of {@link defineMicrosoftProvider}. */
export interface MicrosoftProviderConfig extends PresetConfig {
  clientSecret: string;
  /** `common`, `organizations`, `consumers` or a tenant id. @default "common" */
  tenant?: string;
}

/**
 * Microsoft Entra ID (work, school and personal accounts) as OAuth 2.0, without id_token
 * verification: authorization and token `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/…`,
 * account from Microsoft Graph `GET https://graph.microsoft.com/v1.0/me`. PKCE `S256`; the client
 * secret in the request body. `mail` is not vouched for: `emailVerified` stays unset.
 *
 * @default scopes `["User.Read"]`
 */
export function defineMicrosoftProvider(
  options: MicrosoftProviderConfig,
): OAuthProvider<MicrosoftProfile> {
  const base = `https://login.microsoftonline.com/${encodeURIComponent(options.tenant ?? "common")}/oauth2/v2.0`;
  return defineOAuth2Provider({
    id: options.id ?? "microsoft",
    label: options.label ?? "Microsoft",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: `${base}/authorize`,
    token: `${base}/token`,
    userinfo: "https://graph.microsoft.com/v1.0/me",
    tokenAuth: "body",
    scopes: options.scopes ?? ["User.Read"],
    authorizationParams: options.authorizationParams,
    profile: microsoftProfile,
  });
}

/** Options of {@link defineMicrosoftHandler}: {@link MicrosoftProviderConfig} and `defineSignInHandler`'s, in one object. */
export type MicrosoftHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<MicrosoftProviderConfig, MicrosoftProfile, TResult, TEvent, TLink>;

/**
 * Both legs of a Microsoft sign-in on one route: `defineSignInHandler` on {@link defineMicrosoftProvider}, the
 * options split between them by the provider's keys.
 */
export const defineMicrosoftHandler: PresetHandler<MicrosoftProviderConfig, MicrosoftProfile> =
  /* @__PURE__ */ presetHandler(defineMicrosoftProvider, {
    keys: ["clientId", "clientSecret", "tenant", "scopes", "authorizationParams", "id", "label"],
  });

function microsoftProfile(context: ProfileContext): ProfileResult<MicrosoftProfile> {
  const user = userinfoAs(context, isMicrosoftProfile, { provider: "Microsoft" });
  const result: ProfileResult<MicrosoftProfile> = { subject: user.id, profile: user };
  const name = nonEmpty(user.displayName);
  if (name !== undefined) result.name = name;
  const email = nonEmpty(user.mail);
  if (email !== undefined) result.email = email;
  return result;
}

function isMicrosoftProfile(value: unknown): value is MicrosoftProfile {
  return hasMember(value, "id", "string") && hasMember(value, "userPrincipalName", "string");
}
