import { isRecord, profileError } from "../flow/_http.ts";
import type { ProfileContext } from "../flow/types.ts";

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
