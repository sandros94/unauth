import type { ExpiresIn } from "unjwt/session";
import { computeDurationInSeconds } from "unjwt/utils";
import { type ComposableHooks, composeAuthHooks } from "./_session-hooks.ts";

export const DEFAULT_SESSION_MAX_AGE: ExpiresIn = "7D";
/** `rolling` default: reissue once the token is this fraction of `maxAge` old (a quarter remains). */
export const DEFAULT_ROLLING_AGE = 0.75;

/** The members of a config the auth layer reads or defaults; the rest passes to unjwt as is. */
export interface AuthConfigInput {
  maxAge?: ExpiresIn;
  rolling?: boolean | ExpiresIn;
  name?: string;
  cookie?: false | { secure?: boolean; domain?: string; path?: string; httpOnly?: boolean };
  /** Typed per entry by the public config; read here as {@link ComposableHooks}. */
  hooks?: object;
}

/** The unjwt session config for an auth config: defaults filled in, auth hooks composed. */
export function resolveAuthConfig(config: AuthConfigInput): Record<string, unknown> {
  const maxAge = config.maxAge ?? DEFAULT_SESSION_MAX_AGE;
  return {
    ...config,
    name: config.name ?? defaultSessionName(config.cookie),
    maxAge,
    rolling: resolveRolling(config.rolling, maxAge),
    // A session token is a bearer credential: scripts never need to read it.
    cookie: config.cookie === false ? false : { httpOnly: true, ...config.cookie },
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- each entry names the request argument its own way
    hooks: composeAuthHooks(config.hooks as ComposableHooks | undefined),
  };
}

/**
 * Resolves the `rolling` option into the value unjwt's session config takes: a duration is the
 * age a token must reach before a read reissues it, and it must be shorter than `maxAge`.
 */
export function resolveRolling(
  rolling: boolean | ExpiresIn | undefined,
  maxAge: ExpiresIn,
): true | ExpiresIn | undefined {
  if (rolling === false) return undefined;
  if (rolling === undefined) {
    const age = Math.floor(computeDurationInSeconds(maxAge) * DEFAULT_ROLLING_AGE);
    return age >= 1 ? age : true;
  }
  return rolling;
}

/**
 * `__Host-unauth` on a secure host-only cookie at `/`, `__Secure-unauth` on a secure cookie scoped
 * by `domain` or `path` (which `__Host-` forbids), `unauth` otherwise.
 */
function defaultSessionName(cookie: AuthConfigInput["cookie"]): string {
  if (cookie === false || cookie?.secure === false) return "unauth";
  if (cookie?.domain !== undefined || (cookie?.path ?? "/") !== "/") return "__Secure-unauth";
  return "__Host-unauth";
}
