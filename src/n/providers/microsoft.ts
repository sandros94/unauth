import { oauth2 } from "../flow/oauth2.ts";
import type { ProfileContext, ProfileResult, Provider } from "../flow/types.ts";
import { type PresetOptions, hasMember, nonEmpty, userinfoAs } from "./_shared.ts";

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
export interface MicrosoftProviderOptions extends PresetOptions {
  clientSecret: string;
  /** `common`, `organizations`, `consumers` or a tenant id. @default "common" */
  tenant?: string;
}

/**
 * Microsoft Entra ID (work, school and personal accounts), reading the account from Microsoft
 * Graph. Not run as OpenID Connect: on the multi-tenant endpoints each id_token's `iss` names the
 * user's own tenant, which a fixed-issuer check refuses. `mail` is not vouched for, so
 * `emailVerified` stays unset. @default scopes `["User.Read"]`
 */
export function defineMicrosoftProvider(
  options: MicrosoftProviderOptions,
): Provider<MicrosoftProfile> {
  const base = `https://login.microsoftonline.com/${encodeURIComponent(options.tenant ?? "common")}/oauth2/v2.0`;
  return oauth2({
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
