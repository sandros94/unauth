import { isRecord } from "../../_internal/shared.ts";
import type { UnauthError } from "../../error.ts";
import type { StoredRole } from "../types.ts";
import type { CompiledCatalog, ResolvedRole } from "./compiled.ts";
import { malformed, roleInvalid } from "./errors.ts";
import { type EntryParts, readEntry } from "./grammar.ts";
import { expand, implying, removed } from "./permissions.ts";

/**
 * Why a role gives nothing: it, or a role it references, names a role that is neither a preset
 * nor handed in (`reference`), or references loop back to a role being resolved (`cycle`). `role`
 * is the role holding the entry, `reference` the name it holds.
 */
export interface RoleBreak {
  readonly reason: "reference" | "cycle";
  readonly role: string;
  readonly reference: string;
}

/** A role that gives nothing and withholds nothing. */
export const NO_ROLE: ResolvedRole = Object.freeze({
  gives: new Set<string>(),
  withholds: new Set<string>(),
});

/**
 * Resolves entries to `gives` and `withholds`, wildcards expanded against the catalog: what the
 * referenced roles give, less what they withhold that the entries do not name themselves, plus
 * what the entries include, less what they exclude. An exclusion of a permission reaches every
 * permission that implies it, and an unknown permission is inert. `refer` gives a referenced role,
 * or the break that makes this one give nothing.
 */
export function combineEntries(
  catalog: CompiledCatalog,
  entries: readonly EntryParts[],
  refer: (name: string) => ResolvedRole | RoleBreak,
): ResolvedRole | RoleBreak {
  const includes = new Set<string>();
  const excludes = new Set<string>();
  const inherited = new Set<string>();
  const forbidden = new Set<string>();
  for (const entry of entries) {
    if (entry.kind === "pattern") {
      const set = entry.exclude ? removed(catalog, entry.name) : expand(catalog, entry.name);
      for (const permission of set) (entry.exclude ? excludes : includes).add(permission);
      continue;
    }
    const role = refer(entry.name);
    if (isBreak(role)) return role;
    if (entry.exclude) {
      for (const permission of role.gives) {
        excludes.add(permission);
        for (const above of implying(catalog, permission)) excludes.add(above);
      }
    } else {
      for (const permission of role.gives) inherited.add(permission);
      for (const permission of role.withholds) forbidden.add(permission);
    }
  }
  const gives = new Set<string>(includes);
  for (const permission of inherited) if (!forbidden.has(permission)) gives.add(permission);
  for (const permission of excludes) gives.delete(permission);
  const withholds = new Set<string>(excludes);
  for (const permission of forbidden) if (!includes.has(permission)) withholds.add(permission);
  return { gives, withholds };
}

/** Whether a resolution broke instead of resolving. */
export function isBreak(value: ResolvedRole | RoleBreak): value is RoleBreak {
  return "reason" in value;
}

/** Reads role names against the presets and the stored roles handed in, failing closed. */
export interface RoleReader {
  /** Whether `name` is a preset or a stored role handed in. */
  exists(name: string): boolean;
  /**
   * What `name` gives: the preset of that name when there is one, else the stored role.
   * {@link NO_ROLE} when it is neither, or its role breaks: fails closed, never throws for stale
   * data.
   */
  resolve(name: string): ResolvedRole;
  /** What a stored role resolves to, or why it gives nothing. */
  resolveStored(role: StoredRole): ResolvedRole | RoleBreak;
}

/**
 * A {@link RoleReader} over `roles`. A name that is both a preset and a stored role reads as the
 * preset. A reference met again while it is being resolved breaks the role, as a role that no
 * longer exists does, so every role on a cycle and every role referencing one gives nothing.
 * Throws `ERR_AUTHZ_MALFORMED` for `roles` that is not a list of stored roles, and, once a name is
 * read, for a role of that name whose entries do not match their grammar.
 * `ERR_AUTHZ_ROLE_INVALID` (`duplicate`) for two stored roles of one name. Results are memoized
 * for the reader's life.
 */
export function roleReader(catalog: CompiledCatalog, roles: unknown): RoleReader {
  const byName = indexRoles(roles);
  const memo = new Map<StoredRole, ResolvedRole | RoleBreak>();
  const visiting = new Set<StoredRole>();

  const resolveStored = (role: StoredRole): ResolvedRole | RoleBreak => {
    const known = memo.get(role);
    if (known) return known;
    const entries = role.entries.map((entry) => {
      const parts = readEntry(entry);
      if (!parts) throw entryMalformed(entry);
      return parts;
    });
    visiting.add(role);
    const result = combineEntries(catalog, entries, (name) => {
      const preset = catalog.presets.get(name);
      if (preset) return preset;
      const target = byName.get(name);
      if (!target) return { reason: "reference", role: role.name, reference: name };
      if (visiting.has(target)) return { reason: "cycle", role: role.name, reference: name };
      return resolveStored(target);
    });
    visiting.delete(role);
    memo.set(role, result);
    return result;
  };

  return {
    exists: (name) => catalog.presets.has(name) || byName.has(name),
    resolve: (name) => {
      const preset = catalog.presets.get(name);
      if (preset) return preset;
      const target = byName.get(name);
      if (!target) return NO_ROLE;
      const result = resolveStored(target);
      return isBreak(result) ? NO_ROLE : result;
    },
    resolveStored,
  };
}

/** `ERR_AUTHZ_MALFORMED` (`entry`) for a role entry that does not match its grammar. */
export function entryMalformed(entry: unknown): UnauthError<"ERR_AUTHZ_MALFORMED"> {
  return malformed("The role entry is not written in its one form.", {
    what: "entry",
    value: entry,
  });
}

function indexRoles(roles: unknown): Map<string, StoredRole> {
  const byName = new Map<string, StoredRole>();
  if (roles === undefined) return byName;
  if (!Array.isArray(roles)) throw rolesError(roles);
  for (const role of roles) {
    if (!isStoredRoleShape(role)) throw rolesError(role);
    if (byName.has(role.name)) {
      throw roleInvalid("Two stored roles have the same name.", {
        role: role.name,
        reason: "duplicate",
      });
    }
    byName.set(role.name, role);
  }
  return byName;
}

function isStoredRoleShape(value: unknown): value is StoredRole {
  if (!isRecord(value)) return false;
  const { name, entries } = value;
  return (
    typeof name === "string" &&
    Array.isArray(entries) &&
    entries.every((entry) => typeof entry === "string")
  );
}

function rolesError(value: unknown) {
  return malformed("The stored roles are not in their one form.", { what: "roles", value });
}
