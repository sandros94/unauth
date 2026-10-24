import { configError, profileError } from "../flow/_internal/http/shared.ts";
import { type OidcProfile, claimsProfile, defineOidcProvider } from "../flow/oidc.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import type { WebRequestEvent } from "../request-event.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
} from "./_internal/shared.ts";

/**
 * Cloudflare Access's id_token claims and userinfo
 * (https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/saas-apps/generic-oidc-saas/).
 */
export interface CloudflareAccessProfile extends OidcProfile {
  email?: string;
  email_verified?: boolean;
  name?: string;
  /** The identity provider's groups the account belongs to, with the `groups` scope. */
  groups?: string[];
}

/** Options of {@link defineCloudflareAccessProvider}. */
export interface CloudflareAccessProviderConfig extends PresetConfig {
  /** The Zero Trust team name: `<team>.cloudflareaccess.com`. */
  team: string;
  clientSecret: string;
}

const TEAM = /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i;

/**
 * Cloudflare Zero Trust as the identity provider of an application registered as a SaaS OpenID
 * Connect app (not a consumer Cloudflare account login): discovered from
 * `https://<team>.cloudflareaccess.com/cdn-cgi/access/sso/oidc/<clientId>`, PKCE `S256`, a nonce,
 * the client secret over HTTP Basic. The `groups` scope adds the identity provider's groups to
 * `identity.profile.groups`. Throws `ERR_UNAUTH_CONFIG_INVALID` when `team` is not a DNS label.
 *
 * @default scopes `["openid", "email", "profile"]`
 */
export function defineCloudflareAccessProvider(
  options: CloudflareAccessProviderConfig,
): OAuthProvider<CloudflareAccessProfile> {
  const { team } = options;
  if (!TEAM.test(team)) {
    throw configError(
      `The Cloudflare Access provider needs a "team" of letters, digits and hyphens, got ${JSON.stringify(team)}.`,
    );
  }
  return defineOidcProvider({
    id: options.id ?? "cloudflare-access",
    label: options.label ?? "Cloudflare Access",
    issuer: `https://${team}.cloudflareaccess.com/cdn-cgi/access/sso/oidc/${encodeURIComponent(options.clientId)}`,
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    scopes: options.scopes ?? ["openid", "email", "profile"],
    authorizationParams: options.authorizationParams,
    profile: cloudflareAccessProfile,
  });
}

/** Options of {@link defineCloudflareAccessHandler}: {@link CloudflareAccessProviderConfig} and `defineSignInHandler`'s, in one object. */
export type CloudflareAccessHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<
  CloudflareAccessProviderConfig,
  CloudflareAccessProfile,
  TResult,
  TEvent,
  TLink
>;

/**
 * Both legs of a Cloudflare Access sign-in on one route: `defineSignInHandler` on
 * {@link defineCloudflareAccessProvider}, the options split between them by the provider's keys.
 */
export const defineCloudflareAccessHandler: PresetHandler<
  CloudflareAccessProviderConfig,
  CloudflareAccessProfile
> = /* @__PURE__ */ presetHandler(defineCloudflareAccessProvider, {
  keys: ["team", "clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
});

function cloudflareAccessProfile(context: ProfileContext): ProfileResult<CloudflareAccessProfile> {
  const result = claimsProfile(context);
  const { profile } = result;
  if (!isCloudflareAccessProfile(profile)) {
    throw profileError("The Cloudflare Access account data has no subject.");
  }
  return { ...result, profile };
}

function isCloudflareAccessProfile(value: OidcProfile): value is CloudflareAccessProfile {
  const { groups } = value;
  return (
    typeof value.sub === "string" &&
    (groups === undefined ||
      (Array.isArray(groups) && groups.every((group) => typeof group === "string")))
  );
}
