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

/** `GET /api/v4/user` (https://docs.gitlab.com/api/users/#for-non-administrator-users). */
export interface GitLabProfile {
  id: number;
  username: string;
  name: string;
  state: string;
  avatar_url: string | null;
  web_url: string;
  /** The primary email; with `read_user`. */
  email?: string;
  public_email?: string | null;
  created_at?: string;
  bio?: string;
  location?: string | null;
  locked?: boolean;
  two_factor_enabled?: boolean;
}

/** Options of {@link defineGitLabProvider}. */
export interface GitLabProviderConfig extends PresetConfig {
  clientSecret: string;
  /** A self-managed instance. @default "https://gitlab.com" */
  baseUrl?: string;
}

/**
 * GitLab.com or a self-managed instance (`baseUrl`): authorization `/oauth/authorize`, token
 * `/oauth/token`, account from `GET /api/v4/user`. PKCE `S256`; the client secret in the request
 * body. The payload has no email verification flag: `emailVerified` stays unset.
 *
 * @default scopes `["read_user"]`
 */
export function defineGitLabProvider(options: GitLabProviderConfig): OAuthProvider<GitLabProfile> {
  const base = (options.baseUrl ?? "https://gitlab.com").replace(/\/+$/, "");
  return defineOAuth2Provider({
    id: options.id ?? "gitlab",
    label: options.label ?? "GitLab",
    clientId: options.clientId,
    clientSecret: options.clientSecret,
    authorization: `${base}/oauth/authorize`,
    token: `${base}/oauth/token`,
    userinfo: `${base}/api/v4/user`,
    tokenAuth: "body",
    scopes: options.scopes ?? ["read_user"],
    authorizationParams: options.authorizationParams,
    profile: gitlabProfile,
  });
}

/** Options of {@link defineGitLabHandler}: {@link GitLabProviderConfig} and `defineSignInHandler`'s, in one object. */
export type GitLabHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
> = PresetHandlerConfig<GitLabProviderConfig, GitLabProfile, TResult, TEvent, TMemo>;

/**
 * Both legs of a GitLab sign-in on one route: `defineSignInHandler` on {@link defineGitLabProvider}, the
 * options split between them by the provider's keys.
 */
export const defineGitLabHandler: PresetHandler<GitLabProviderConfig, GitLabProfile> =
  /* @__PURE__ */ presetHandler(defineGitLabProvider, {
    keys: ["clientId", "clientSecret", "baseUrl", "scopes", "authorizationParams", "id", "label"],
  });

function gitlabProfile(context: ProfileContext): ProfileResult<GitLabProfile> {
  const user = userinfoAs(context, isGitLabProfile, { provider: "GitLab" });
  const result: ProfileResult<GitLabProfile> = {
    subject: String(user.id),
    profile: user,
    name: nonEmpty(user.name) ?? user.username,
  };
  const email = nonEmpty(user.email);
  if (email !== undefined) result.email = email;
  const avatar = nonEmpty(user.avatar_url);
  if (avatar !== undefined) result.avatar = avatar;
  return result;
}

function isGitLabProfile(value: unknown): value is GitLabProfile {
  return hasMember(value, "id", "number") && hasMember(value, "username", "string");
}
