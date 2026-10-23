import { configError } from "./_internal/http/shared.ts";
import type { OAuthProvider } from "./types.ts";

/** Parameters the flow owns; extra parameters naming them are dropped. */
const RESERVED = new Set([
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "response_mode",
]);

/** What one authorization request carries besides the provider's own parameters. */
export interface AuthorizationParams {
  redirectUri: string;
  state: string;
  /** The challenge half of `createPkce()`; required unless the provider has `pkce: false`. */
  pkce?: { challenge: string; method: "S256" | "plain" };
  nonce?: string;
  /** Replaces the provider's scopes. */
  scopes?: string[];
  /** Extra query parameters; they never replace the ones above. */
  params?: Record<string, string>;
}

/** The authorization-code request URL (RFC 6749 §4.1.1) for a provider with resolved endpoints. */
export function buildAuthorizationUrl(
  provider: OAuthProvider<unknown>,
  params: AuthorizationParams,
): URL {
  if (!provider.authorization) {
    throw configError(
      `OAuthProvider ${JSON.stringify(provider.id)} has no "authorization" endpoint yet; pass it through resolveProvider() first.`,
    );
  }
  if (provider.pkce && !params.pkce) {
    throw configError(
      `OAuthProvider ${JSON.stringify(provider.id)} uses PKCE; pass "pkce" from createPkce().`,
    );
  }
  const url = new URL(provider.authorization);
  const query = url.searchParams;
  for (const [name, value] of Object.entries({
    ...provider.authorizationParams,
    ...params.params,
  })) {
    if (!RESERVED.has(name)) query.set(name, value);
  }
  query.set("response_type", "code");
  query.set("client_id", provider.client.id);
  query.set("redirect_uri", params.redirectUri);
  const scopes = params.scopes ?? provider.scopes;
  if (scopes.length > 0) query.set("scope", scopes.join(provider.scopeSeparator));
  query.set("state", params.state);
  if (params.nonce !== undefined) query.set("nonce", params.nonce);
  if (provider.pkce && params.pkce) {
    query.set("code_challenge", params.pkce.challenge);
    query.set("code_challenge_method", params.pkce.method);
  }
  if (provider.responseMode === "form_post") query.set("response_mode", "form_post");
  return url;
}
