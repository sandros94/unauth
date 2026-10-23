import { profileError } from "../flow/_http.ts";
import { getJson } from "../flow/_http-json.ts";
import { defineOAuth2Provider } from "../flow/oauth2.ts";
import type { ProfileContext, ProfileResult, OAuthProvider } from "../flow/types.ts";
import type { WebRequestEvent } from "../request-event.ts";
import {
  type PresetConfig,
  type PresetHandler,
  type PresetHandlerConfig,
  presetHandler,
  grantedScopes,
  hasMember,
  nonEmpty,
  userinfoAs,
} from "./_shared.ts";

/** `GET /user` (https://docs.github.com/en/rest/users/users#get-the-authenticated-user). */
export interface GitHubProfile {
  id: number;
  login: string;
  node_id: string;
  avatar_url: string;
  html_url: string;
  type: string;
  site_admin: boolean;
  name: string | null;
  /** The public profile email; `null` when the user keeps it private. */
  email: string | null;
  company?: string | null;
  blog?: string | null;
  location?: string | null;
  bio?: string | null;
  twitter_username?: string | null;
  public_repos?: number;
  followers?: number;
  following?: number;
  created_at: string;
  updated_at: string;
}

/** An entry of `GET /user/emails`. */
export interface GitHubEmail {
  email: string;
  primary: boolean;
  verified: boolean;
  visibility: "public" | "private" | null;
}

/** Options of {@link defineGitHubProvider}. */
export interface GitHubProviderConfig extends PresetConfig {
  clientSecret: string;
}

const API = "https://api.github.com";
/** GitHub's REST API refuses requests without a User-Agent. */
const HEADERS = { "user-agent": "unauth", "accept": "application/vnd.github+json" };

/**
 * GitHub (OAuth app or GitHub App user authorization): authorization
 * `https://github.com/login/oauth/authorize`, token `https://github.com/login/oauth/access_token`,
 * account from `GET https://api.github.com/user`. PKCE `S256`; the client secret in the request
 * body. With `user:email` granted, `email` and `emailVerified` come from the primary entry of
 * `GET /user/emails`; without it, `email` is the public profile address and `emailVerified` stays
 * unset.
 *
 * @default scopes `["read:user", "user:email"]`
 */
export function defineGitHubProvider(options: GitHubProviderConfig): OAuthProvider<GitHubProfile> {
  return defineOAuth2Provider({
    id: options.id ?? "github",
    label: options.label ?? "GitHub",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: "https://github.com/login/oauth/authorize",
    token: "https://github.com/login/oauth/access_token",
    userinfo: `${API}/user`,
    userinfoHeaders: HEADERS,
    tokenAuth: "body",
    scopes: options.scopes ?? ["read:user", "user:email"],
    authorizationParams: options.authorizationParams,
    profile: githubProfile,
  });
}

/** Options of {@link defineGitHubHandler}: {@link GitHubProviderConfig} and `defineSignInHandler`'s, in one object. */
export type GitHubHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<GitHubProviderConfig, GitHubProfile, TResult, TEvent, TLink>;

/**
 * Both legs of a GitHub sign-in on one route: `defineSignInHandler` on {@link defineGitHubProvider}, the
 * options split between them by the provider's keys.
 */
export const defineGitHubHandler: PresetHandler<GitHubProviderConfig, GitHubProfile> =
  /* @__PURE__ */ presetHandler(defineGitHubProvider, {
    keys: ["clientId", "clientSecret", "scopes", "authorizationParams", "id", "label"],
  });

async function githubProfile(context: ProfileContext): Promise<ProfileResult<GitHubProfile>> {
  const user = userinfoAs(context, isGitHubProfile, { provider: "GitHub" });
  const result: ProfileResult<GitHubProfile> = {
    subject: String(user.id),
    profile: user,
    name: nonEmpty(user.name) ?? user.login,
    avatar: user.avatar_url,
  };
  if (grantedScopes(context.tokens.scope).includes("user:email")) {
    const emails = await getJson(`${API}/user/emails`, {
      fetch: context.fetch,
      headers: { ...HEADERS, authorization: `Bearer ${context.tokens.access_token}` },
      label: "GitHub email list",
    });
    if (!Array.isArray(emails)) throw profileError("The GitHub email list is not an array.");
    const primary = emails.filter(isGitHubEmail).find((entry) => entry.primary);
    if (primary) {
      result.email = primary.email;
      result.emailVerified = primary.verified;
    }
  } else if (user.email) {
    result.email = user.email;
  }
  return result;
}

function isGitHubProfile(value: unknown): value is GitHubProfile {
  return hasMember(value, "id", "number") && hasMember(value, "login", "string");
}

function isGitHubEmail(value: unknown): value is GitHubEmail {
  return hasMember(value, "email", "string");
}
