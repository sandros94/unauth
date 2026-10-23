import { profileError } from "../flow/_http.ts";
import { type OidcProfile, claimsProfile, defineOidcProvider } from "../flow/oidc.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import type { AuthSessionData } from "../_session-data.ts";
import type { HandlerEvent } from "../handler.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
} from "./_shared.ts";

/** Google's id_token claims and userinfo (https://developers.google.com/identity/openid-connect/openid-connect#obtainuserinfo). */
export interface GoogleProfile extends OidcProfile {
  email?: string;
  email_verified?: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  locale?: string;
  /** The Google Workspace domain of the account. */
  hd?: string;
}

/** Options of {@link defineGoogleProvider}. */
export interface GoogleProviderConfig extends PresetConfig {
  clientSecret: string;
}

/**
 * Google, as an OpenID Connect provider discovered from `https://accounts.google.com`.
 * Restrict to a Workspace domain by checking `identity.profile.hd` (the `hd` authorization
 * parameter is only a hint). @default scopes `["openid", "email", "profile"]`
 */
export function defineGoogleProvider(options: GoogleProviderConfig): OAuthProvider<GoogleProfile> {
  return defineOidcProvider({
    id: options.id ?? "google",
    label: options.label ?? "Google",
    issuer: "https://accounts.google.com",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    scopes: options.scopes ?? ["openid", "email", "profile"],
    authorizationParams: options.authorizationParams,
    profile: googleProfile,
  });
}

/** Options of {@link defineGoogleHandler}: {@link GoogleProviderConfig} and `defineSignInHandler`'s, in one object. */
export type GoogleHandlerConfig<
  TSession extends object = AuthSessionData,
  TResult = never,
  TEvent extends HandlerEvent = HandlerEvent,
> = PresetHandlerConfig<GoogleProviderConfig, GoogleProfile, TSession, TResult, TEvent>;

/**
 * Both legs of a Google sign-in on one route: `defineSignInHandler` on {@link defineGoogleProvider}, the
 * options split between them by the provider's keys.
 */
export const defineGoogleHandler: PresetHandler<GoogleProviderConfig, GoogleProfile> =
  /* @__PURE__ */ presetHandler(defineGoogleProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function googleProfile(context: ProfileContext): ProfileResult<GoogleProfile> {
  const result = claimsProfile(context);
  const { profile } = result;
  if (!isGoogleProfile(profile)) throw profileError("The Google account data has no subject.");
  return { ...result, profile };
}

function isGoogleProfile(value: OidcProfile): value is GoogleProfile {
  return typeof value.sub === "string" && (value.hd === undefined || typeof value.hd === "string");
}
