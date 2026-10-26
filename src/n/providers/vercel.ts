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

/** Vercel's id_token claims and userinfo (https://vercel.com/docs/sign-in-with-vercel/authorization-server-api). */
export interface VercelProfile extends OidcProfile {
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  picture?: string;
}

/** Options of {@link defineVercelProvider}. */
export interface VercelProviderConfig extends PresetConfig {
  /** Confidential clients authenticate with HTTP Basic; public clients leave it out. */
  clientSecret?: string;
}

/**
 * Sign in with Vercel, OpenID Connect discovered from `https://vercel.com`: PKCE `S256`, which
 * Vercel requires, a nonce, the client secret over HTTP Basic, or a public client without one.
 * Add `offline_access` to `scopes` when the application wants a refresh token.
 *
 * @default scopes `["openid", "email", "profile"]`
 */
export function defineVercelProvider(options: VercelProviderConfig): OAuthProvider<VercelProfile> {
  return defineOidcProvider({
    id: options.id ?? "vercel",
    label: options.label ?? "Vercel",
    issuer: "https://vercel.com",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    tokenAuth: options.clientSecret ? "basic" : "none",
    scopes: options.scopes ?? ["openid", "email", "profile"],
    authorizationParams: options.authorizationParams,
    profile: vercelProfile,
  });
}

/** Options of {@link defineVercelHandler}: {@link VercelProviderConfig} and `defineSignInHandler`'s, in one object. */
export type VercelHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
> = PresetHandlerConfig<VercelProviderConfig, VercelProfile, TResult, TEvent, TMemo>;

/**
 * Both legs of a Vercel sign-in on one route: `defineSignInHandler` on {@link defineVercelProvider}, the
 * options split between them by the provider's keys.
 */
export const defineVercelHandler: PresetHandler<VercelProviderConfig, VercelProfile> =
  /* @__PURE__ */ presetHandler(defineVercelProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

function vercelProfile(context: ProfileContext): ProfileResult<VercelProfile> {
  const result = claimsProfile(context);
  const { profile } = result;
  if (!isVercelProfile(profile)) throw profileError("The Vercel account data has no subject.");
  return { ...result, profile };
}

function isVercelProfile(value: OidcProfile): value is VercelProfile {
  return typeof value.sub === "string";
}
