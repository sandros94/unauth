import { profileError } from "./_http.ts";
import { standardProfile } from "./_profile.ts";
import type { OAuthClientSecret, ProfileMapper } from "./oauth2.ts";
import { defineProvider } from "./provider.ts";
import type {
  IdTokenClaims,
  ProfileContext,
  ProfileResult,
  OAuthProvider,
  ProviderConfig,
} from "./types.ts";

/** The OpenID Connect standard claims (OIDC Core §5.1) a provider may return. */
export interface OidcProfile extends Partial<IdTokenClaims> {
  sub: string;
  name?: string;
  given_name?: string;
  family_name?: string;
  preferred_username?: string;
  email?: string;
  email_verified?: boolean;
  picture?: string;
  locale?: string;
}

/** Options of {@link defineOidcProvider}. */
export interface OidcProviderConfig extends Pick<
  ProviderConfig,
  | "label"
  | "pkce"
  | "tokenAuth"
  | "responseMode"
  | "authorizationParams"
  | "tokenParams"
  | "userinfoHeaders"
  | "insecureHosts"
> {
  /** The issuer identifier; endpoints come from its discovery document. */
  issuer: string;
  clientId: string;
  clientSecret?: OAuthClientSecret;
  /** @default "oidc" */
  id?: string;
  /** @default ["openid", "profile", "email"] */
  scopes?: string[];
}

/**
 * A generic OpenID Connect provider: discovery, PKCE, a nonce, id_token verification and the
 * userinfo endpoint when the issuer has one. Without `profile`, the account is the id_token claims
 * merged over userinfo.
 */
export function defineOidcProvider(options: OidcProviderConfig): OAuthProvider<OidcProfile>;
export function defineOidcProvider<TProfile>(
  options: OidcProviderConfig & { profile: ProfileMapper<TProfile> },
): OAuthProvider<TProfile>;
export function defineOidcProvider(
  options: OidcProviderConfig & { profile?: ProfileMapper<unknown> },
): OAuthProvider<unknown> {
  const {
    clientId,
    clientSecret,
    profile,
    id = "oidc",
    scopes = ["openid", "profile", "email"],
    ...rest
  } = options;
  return defineProvider<unknown>({
    ...rest,
    id,
    scopes,
    kind: "oidc",
    discovery: true,
    nonce: true,
    client: { id: clientId, secret: clientSecret },
    profile: profile ?? claimsProfile,
  });
}

/** The id_token claims merged over userinfo, read through the standard claims. */
export function claimsProfile(context: ProfileContext): ProfileResult<OidcProfile> {
  const { claims } = context;
  if (!claims) throw profileError("The OpenID Connect sign-in carried no id_token claims.");
  const profile: OidcProfile = { ...context.userinfo, ...claims };
  return standardProfile(profile);
}
