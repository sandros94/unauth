import type { CompiledCatalog } from "./compiled.ts";
import { malformed, permissionUnknown, questionInvalid } from "./errors.ts";
import { isPattern } from "./grammar.ts";

/**
 * The declared permissions a pattern stands for: itself when declared, every declared one of the
 * resource for `resource:*`, of the action for `*:action`, all for `*`. Empty for an unknown
 * permission, a wildcard that matches nothing, or a value that is not a pattern.
 */
export function expand(catalog: CompiledCatalog, pattern: string): ReadonlySet<string> {
  if (pattern === "*") return catalog.permissions;
  const colon = pattern.indexOf(":");
  if (colon < 0) return EMPTY;
  const resource = pattern.slice(0, colon);
  const action = pattern.slice(colon + 1);
  if (resource === "*") return catalog.byAction.get(action) ?? EMPTY;
  if (action === "*") return catalog.byResource.get(resource) ?? EMPTY;
  return catalog.permissions.has(pattern) ? new Set([pattern]) : EMPTY;
}

/** Every permission `permission` implies, directly or through a chain, itself left out. */
export function implied(catalog: CompiledCatalog, permission: string): ReadonlySet<string> {
  return catalog.implies.get(permission) ?? EMPTY;
}

/** Every permission that implies `permission`, directly or through a chain, itself left out. */
export function implying(catalog: CompiledCatalog, permission: string): ReadonlySet<string> {
  return catalog.impliedBy.get(permission) ?? EMPTY;
}

/** What a deny must name, once expanded, to block `permission`: itself and everything it implies. */
export function blocking(catalog: CompiledCatalog, permission: string): Set<string> {
  return new Set([permission, ...implied(catalog, permission)]);
}

/** What satisfies a question about `permission`: itself and everything that implies it. */
export function wanted(catalog: CompiledCatalog, permission: string): Set<string> {
  return new Set([permission, ...implying(catalog, permission)]);
}

/**
 * What an exclusion or a deny of `pattern` reaches: its expansion and everything that implies one
 * of those. Empty for an unknown permission.
 */
export function removed(catalog: CompiledCatalog, pattern: string): Set<string> {
  const out = new Set<string>();
  for (const permission of expand(catalog, pattern)) {
    out.add(permission);
    for (const above of implying(catalog, permission)) out.add(above);
  }
  return out;
}

/**
 * What an exclusion must name, once expanded, to take out something that satisfies a question
 * about `permission`: {@link wanted} and everything one of those implies.
 */
export function down(catalog: CompiledCatalog, permission: string): Set<string> {
  const out = new Set<string>();
  for (const satisfying of wanted(catalog, permission)) {
    out.add(satisfying);
    for (const below of implied(catalog, satisfying)) out.add(below);
  }
  return out;
}

/**
 * The four values that can carry a concrete permission, as written in a statement or an entry:
 * itself, `resource:*`, `*:action` and `*`.
 */
export function spellings(permission: string): [string, string, string, string] {
  const colon = permission.indexOf(":");
  return [permission, `${permission.slice(0, colon)}:*`, `*:${permission.slice(colon + 1)}`, "*"];
}

/**
 * `value` when it may be asked in a question: `ERR_AUTHZ_QUESTION_INVALID` (`wildcard`) for a
 * pattern, `ERR_AUTHZ_MALFORMED` for anything that is not a pattern, `ERR_AUTHZ_PERMISSION_UNKNOWN`
 * for a permission the catalog does not declare.
 */
export function assertQuestionPermission(catalog: CompiledCatalog, value: unknown): string {
  if (!isPattern(value)) {
    throw malformed("The permission is not written in its one form.", {
      what: "permission",
      value,
    });
  }
  if (value.includes("*")) throw questionInvalid("wildcard");
  if (!catalog.permissions.has(value)) throw permissionUnknown(value);
  return value;
}

/**
 * `value` when it may be the value of an allow, a deny or an exclusion being placed, or a
 * permission entry of a role being defined: `ERR_AUTHZ_MALFORMED` for anything that is not a
 * pattern, `ERR_AUTHZ_PERMISSION_UNKNOWN` for one that expands to no declared permission.
 */
export function assertPattern(catalog: CompiledCatalog, value: unknown): string {
  if (!isPattern(value)) {
    throw malformed("The permission is not written in its one form.", { what: "pattern", value });
  }
  if (expand(catalog, value).size === 0) throw permissionUnknown(value);
  return value;
}

const EMPTY: ReadonlySet<string> = new Set();
