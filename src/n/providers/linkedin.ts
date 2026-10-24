import { profileError } from "../flow/_internal/http/shared.ts";
import { type OidcProfile, claimsProfile, defineOidcProvider } from "../flow/oidc.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import type { WebRequestEvent } from "../request-event.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
} from "./_internal/shared.ts";

/** LinkedIn's OpenID Connect claims (https://learn.microsoft.com/linkedin/consumer/integrations/self-serve/sign-in-with-linkedin-v2). */
export interface LinkedInProfile extends Omit<OidcProfile, "locale"> {
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  email?: string;
  email_verified?: boolean;
  /** An object here, not the standard string. */
  locale?: { country?: string; language?: string } | string;
}

/** Options of {@link defineLinkedInProvider}. */
export interface LinkedInProviderConfig extends PresetConfig {
  clientSecret: string;
  /** Send PKCE S256, for an app LinkedIn enabled it for. @default false */
  pkce?: boolean;
}

/**
 * LinkedIn ("Sign In with LinkedIn using OpenID Connect"), discovered from
 * `https://www.linkedin.com/oauth`: a nonce, the client secret in the request body. PKCE is off
 * unless `pkce: true`; LinkedIn enables it per app, for native apps
 * (https://learn.microsoft.com/en-us/linkedin/shared/authentication/authorization-code-flow-native).
 *
 * @default scopes `["openid", "profile", "email"]`
 */
export function defineLinkedInProvider(
  options: LinkedInProviderConfig,
): OAuthProvider<LinkedInProfile> {
  return defineOidcProvider({
    id: options.id ?? "linkedin",
    label: options.label ?? "LinkedIn",
    issuer: "https://www.linkedin.com/oauth",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    tokenAuth: "body",
    pkce: options.pkce ?? false,
    scopes: options.scopes ?? ["openid", "profile", "email"],
    authorizationParams: options.authorizationParams,
    profile: linkedinProfile,
  });
}

/** Options of {@link defineLinkedInHandler}: {@link LinkedInProviderConfig} and `defineSignInHandler`'s, in one object. */
export type LinkedInHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
> = PresetHandlerConfig<LinkedInProviderConfig, LinkedInProfile, TResult, TEvent, TMemo>;

/**
 * Both legs of a LinkedIn sign-in on one route: `defineSignInHandler` on {@link defineLinkedInProvider}, the
 * options split between them by the provider's keys.
 */
export const defineLinkedInHandler: PresetHandler<LinkedInProviderConfig, LinkedInProfile> =
  /* @__PURE__ */ presetHandler(defineLinkedInProvider, {
    keys: ["clientId", "clientSecret", "pkce", "scopes", "authorizationParams", "id", "label"],
  });

function linkedinProfile(context: ProfileContext): ProfileResult<LinkedInProfile> {
  const result = claimsProfile(context);
  const { profile } = result;
  if (!isLinkedInProfile(profile)) throw profileError("The LinkedIn account data has no subject.");
  return { ...result, profile };
}

function isLinkedInProfile(value: Record<string, unknown>): value is LinkedInProfile {
  return typeof value.sub === "string";
}
