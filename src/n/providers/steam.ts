import { configError } from "../flow/_internal/http/shared.ts";
import { defineProvider } from "../flow/provider.ts";
import type { CustomProvider } from "../flow/types.ts";
import type { WebRequestEvent } from "../request-event.ts";
import { type PresetHandler, type PresetHandlerConfig, presetHandler } from "./_internal/shared.ts";
import { complete, start } from "./_internal/steam/flow.ts";
import type { SteamProfile } from "./_internal/steam/profile.ts";

export type { SteamProfile } from "./_internal/steam/profile.ts";

/** Options of {@link defineSteamProvider}. */
export interface SteamProviderConfig {
  /**
   * A Steam Web API key (https://steamcommunity.com/dev/apikey): with one, the account's player
   * summary (persona name, avatar…) is fetched server-side after the sign-in; without one, the
   * identity is the SteamID64 alone. The key never leaves the server.
   */
  apiKey?: string;
  /** The callback URL, used when the sign-in handler names none; Steam registers none. */
  redirectUri?: string;
  /** @default "steam" */
  id?: string;
  /** @default "Steam" */
  label?: string;
}

/**
 * Steam, which speaks OpenID 2.0 rather than OAuth: the user is sent to
 * `https://steamcommunity.com/openid/login`, the assertion that comes back is checked (its
 * endpoint, return URL, identifiers and signed fields) and verified directly at Steam
 * (OpenID 2.0 §11.4.2); the subject is the 17-digit SteamID64 the claimed identifier carries. No
 * tokens, scopes or email exist. Throws `ERR_UNAUTH_CONFIG_INVALID` for an empty `apiKey`.
 */
export function defineSteamProvider(config: SteamProviderConfig): CustomProvider<SteamProfile> {
  const { apiKey } = config;
  if (apiKey === "") throw configError(`The Steam "apiKey" must not be empty when given.`);
  const provider = defineProvider<SteamProfile>({
    id: config.id ?? "steam",
    kind: "custom",
    label: config.label ?? "Steam",
    start,
    complete: (context) => complete(context, { apiKey }),
  });
  return config.redirectUri === undefined
    ? provider
    : { ...provider, redirectUri: config.redirectUri };
}

/** Options of {@link defineSteamHandler}: {@link SteamProviderConfig} and `defineSignInHandler`'s, in one object. */
export type SteamHandlerConfig<
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TLink = never,
> = PresetHandlerConfig<SteamProviderConfig, SteamProfile, TResult, TEvent, TLink>;

/**
 * Both legs of a Steam sign-in on one route: `defineSignInHandler` on {@link defineSteamProvider},
 * the options split between them by the provider's keys. `redirectUri` is both the provider's
 * callback and the sign-in's.
 */
export const defineSteamHandler: PresetHandler<SteamProviderConfig, SteamProfile> =
  /* @__PURE__ */ presetHandler(defineSteamProvider, {
    keys: ["apiKey", "redirectUri", "id", "label"],
    shared: ["redirectUri"],
  });
