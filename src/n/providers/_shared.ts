import type { AuthSessionData } from "../_session-data.ts";
import { isRecord, profileError } from "../flow/_http.ts";
import type { ProfileContext, Provider } from "../flow/types.ts";
import type { SignInKey } from "../_flow-key.ts";
import type { FlowIntent, HandlerEvent } from "../handler.ts";
import {
  type ResponseEnding,
  type SessionEnding,
  type SignInFlowOptions,
  type SignInHandlerOptions,
  type ToSession,
  defineSignInHandler,
} from "../sign-in.ts";

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
  TSession extends object = AuthSessionData,
  TResult = never,
  TEvent extends HandlerEvent = HandlerEvent,
> = TConfig & SignInHandlerOptions<TProfile, TSession, TResult, TEvent>;

/** A preset's sign-in route: {@link defineSignInHandler}, with its overloads, on the provider its own options define. */
export interface PresetHandler<TConfig, TProfile> {
  <TResult = never, TEvent extends HandlerEvent = HandlerEvent>(
    options: TConfig &
      SignInFlowOptions<TResult, TEvent> &
      SignInKey &
      SessionEnding<TProfile, AuthSessionData, TResult, TEvent> & { toSession?: never },
  ): (event: TEvent) => Promise<Response | TResult>;
  <TSession extends object, TResult = never, TEvent extends HandlerEvent = HandlerEvent>(
    options: TConfig &
      SignInFlowOptions<TResult, TEvent> &
      SignInKey &
      SessionEnding<TProfile, TSession, TResult, TEvent> & {
        toSession: ToSession<TSession, TEvent, TProfile>;
      },
  ): (event: TEvent) => Promise<Response | TResult>;
  <TResult, TEvent extends HandlerEvent = HandlerEvent>(
    options: TConfig &
      SignInFlowOptions<TResult, TEvent> &
      SignInKey &
      ResponseEnding<TProfile, TResult, TEvent>,
  ): (event: TEvent) => Promise<Response | TResult>;
}

/**
 * The {@link PresetHandler} of `define`: the members `keys` names, every member of its config and
 * nothing else, go to `define`, the others to {@link defineSignInHandler}; `shared` ones go to both.
 * `login` reads the account from the request when the application's `onStart` names none.
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
    login?: (event: HandlerEvent) => string | undefined;
  },
): PresetHandler<TConfig, TProfile> {
  const keys = new Set<PropertyKey>(options.keys);
  const shared = new Set<PropertyKey>(options.shared);
  const { login } = options;
  const handler = (all: PresetHandlerConfig<TConfig, TProfile, object, unknown>) => {
    const config: Record<string, unknown> = {};
    const signIn: Record<string, unknown> = {};
    for (const [name, value] of Object.entries(all)) {
      if (keys.has(name)) config[name] = value;
      if (!keys.has(name) || shared.has(name)) signIn[name] = value;
    }
    if (login) {
      const { onStart } = all;
      signIn.onStart = async (event: HandlerEvent): Promise<FlowIntent> => {
        const intent = (await onStart?.(event)) ?? {};
        return intent.login === undefined ? { ...intent, login: login(event) } : intent;
      };
    }
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- `all` is checked whole by `PresetHandler`, then split by name: each half is what its callee declares
    return (defineSignInHandler as SplitSignIn<TProfile>)(define(config as TConfig), signIn);
  };
  return handler;
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
type SplitSignIn<TProfile> = (
  provider: Provider<TProfile>,
  options: object,
) => (event: HandlerEvent) => Promise<unknown>;
