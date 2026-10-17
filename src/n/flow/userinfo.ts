import { type Fetch, configError, fetchOf } from "./_http.ts";
import { getObject } from "./_http-json.ts";
import type { OAuthTokens, Provider } from "./types.ts";

/**
 * Reads the provider's userinfo endpoint with the access token. Failures throw
 * `ERR_AUTHN_PROVIDER_ERROR`; prototype-polluting keys are dropped.
 */
export function fetchProfile(
  provider: Provider<unknown>,
  options: { tokens: OAuthTokens; fetch?: Fetch },
): Promise<Record<string, unknown>> {
  if (!provider.userinfo) {
    throw configError(`Provider ${JSON.stringify(provider.id)} has no "userinfo" endpoint.`);
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
