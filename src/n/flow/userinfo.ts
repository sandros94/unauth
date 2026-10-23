import { type Fetch, configError, fetchOf } from "./_internal/http/shared.ts";
import { getObject } from "./_internal/http/json.ts";
import type { OAuthTokens, OAuthProvider } from "./types.ts";

/**
 * Reads the provider's userinfo endpoint with the access token. Failures throw
 * `ERR_AUTHN_PROVIDER_ERROR`; prototype-polluting keys are dropped.
 */
export function fetchProfile(
  provider: OAuthProvider<unknown>,
  options: { tokens: OAuthTokens; fetch?: Fetch },
): Promise<Record<string, unknown>> {
  if (!provider.userinfo) {
    throw configError(`OAuthProvider ${JSON.stringify(provider.id)} has no "userinfo" endpoint.`);
  }
  return getObject(provider.userinfo, {
    fetch: fetchOf(options),
    headers: {
      ...provider.userinfoHeaders,
      authorization: `Bearer ${options.tokens.access_token}`,
    },
    label: "userinfo endpoint",
  });
}
