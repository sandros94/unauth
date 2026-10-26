import { isRecord, profileError } from "../../flow/_internal/http/shared.ts";
import type { ProfileContext, Provider } from "../../flow/types.ts";
import type { WebRequestEvent } from "../../request-event.ts";
import {
  type SignInAnswer,
  type SignInHandlerOptions,
  defineSignInHandler,
} from "../../sign-in.ts";

/** What every preset accepts besides its own options. */
export interface PresetConfig {
  clientId: string;
  /** Replaces the preset's default scopes. */
  scopes?: string[];
  /** Extra authorization parameters (`prompt`, `login_hint`…). */
  authorizationParams?: Record<string, string>;
  /** Another `id`, to register the same provider twice (two tenants, two apps). */
  id?: string;
  label?: string;
}

/** Options of a preset's sign-in route: its provider's and {@link defineSignInHandler}'s in one object. */
export type PresetHandlerConfig<
  TConfig,
  TProfile,
  TResult = never,
  TEvent extends WebRequestEvent = WebRequestEvent,
  TMemo = never,
> = TConfig & SignInHandlerOptions<TProfile, TResult, TEvent, TMemo>;

/** A preset's sign-in route: {@link defineSignInHandler} on the provider its own options define. */
export interface PresetHandler<TConfig, TProfile> {
  <TResult = never, TEvent extends WebRequestEvent = WebRequestEvent, TMemo = never>(
    options: PresetHandlerConfig<TConfig, TProfile, TResult, TEvent, TMemo>,
  ): (event: TEvent) => Promise<Response | SignInAnswer<TResult>>;
}

/**
 * The {@link PresetHandler} of `define`: the members `keys` names, every member of its config and
 * nothing else, go to `define`, the others to {@link defineSignInHandler}; `shared` ones go to both.
 */
export function presetHandler<
  TConfig extends object,
  TProfile,
  const TKeys extends readonly (keyof TConfig)[],
>(
  define: (config: TConfig) => Provider<TProfile>,
  options: {
    keys: TKeys & CoveringKeys<TConfig, TKeys>;
    shared?: readonly TKeys[number][];
  },
): PresetHandler<TConfig, TProfile> {
  const keys = new Set<PropertyKey>(options.keys);
  const shared = new Set<PropertyKey>(options.shared);
  return <TResult, TEvent extends WebRequestEvent, TMemo>(
    all: PresetHandlerConfig<TConfig, TProfile, TResult, TEvent, TMemo>,
  ): ((event: TEvent) => Promise<Response | SignInAnswer<TResult>>) => {
    const config: Record<string, unknown> = {};
    const signIn: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(all)) {
      if (keys.has(name)) config[name] = value;
      if (!keys.has(name) || shared.has(name)) signIn[name] = value;
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `all` is checked whole by `PresetHandler`, then split by name: each half is what its callee declares
    const provider = define(config as TConfig);
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the sign-in's half of the same split
    return (defineSignInHandler as SplitSignIn<TProfile, TResult, TEvent>)(provider, signIn);
  };
}

/** The userinfo payload when `guard` accepts it, else `ERR_AUTHN_PROFILE_INVALID`. */
export function userinfoAs<T>(
  context: ProfileContext,
  guard: (value: unknown) => value is T,
  options: { provider: string },
): T {
  const { userinfo } = context;
  if (!guard(userinfo)) {
    throw profileError(`The ${options.provider} account data does not have the expected shape.`);
  }
  return userinfo;
}

/** Whether `value` is an object whose `name` member has the JavaScript type `type`. */
export function hasMember(value: unknown, name: string, type: "string" | "number"): boolean {
  return isRecord(value) && typeof value[name] === type;
}

/** `value` when it is a non-empty string. */
export function nonEmpty(value: unknown): string | undefined {
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** A boolean claim some providers send as `"true"` / `"false"`. */
export function booleanClaim(value: unknown): boolean | undefined {
  if (typeof value === "boolean") return value;
  return value === "true" || value === "false" ? value === "true" : undefined;
}

/** The scopes a token response says were granted (comma- or space-separated). */
export function grantedScopes(scope: string | undefined): string[] {
  return scope ? scope.split(/[\s,]+/).filter(Boolean) : [];
}

/** `unknown` when `TKeys` names every member of `TConfig`; else the missing ones, as a type error. */
type CoveringKeys<TConfig, TKeys extends readonly PropertyKey[]> = [
  Exclude<keyof TConfig, TKeys[number]>,
] extends [never]
  ? unknown
  : { missing: Exclude<keyof TConfig, TKeys[number]> };

/** {@link defineSignInHandler} on options split at run time, after their type was checked whole. */
type SplitSignIn<TProfile, TResult, TEvent> = (
  provider: Provider<TProfile>,
  options: object,
) => (event: TEvent) => Promise<Response | SignInAnswer<TResult>>;
