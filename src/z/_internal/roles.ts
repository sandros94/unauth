import { isRecord } from "../../_internal/shared.ts";
import type { StoredRole } from "../types.ts";
import type { CompiledCatalog, ResolvedRole } from "./compiled.ts";
import { malformed } from "./errors.ts";
import { type EntryParts, compareBytes, readEntry } from "./grammar.ts";
import { assertKey, covers } from "./keys.ts";
import { expand, implying, removed } from "./permissions.ts";
import { fits } from "./structure.ts";

/**
 * Why a role gives nothing: it, or a role it references, names a role unknown at its home
 * (`reference`), one of two stored roles of one name visible there (`ambiguous`), or references
 * loop (`cycle`). `role` is the role holding the entry, `reference` the name it holds.
 */
export interface RoleBreak {
  readonly reason: "reference" | "ambiguous" | "cycle";
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

/** Reads role names against the presets and a set of stored roles, failing closed. */
export interface RoleReader {
  /** Whether `name` is a preset, or a stored role whose home covers `at`, a canonical key. */
  exists(name: string, at: string): boolean;
  /**
   * The stored role `name` reads as at `at`: `undefined` for a preset (which wins over a stored
   * role of the same name), for no stored role visible there, and for two of them.
   */
  stored(name: string, at: string): StoredRole | undefined;
  /**
   * What `name` gives read at `at`. {@link NO_ROLE} when the name is unknown there, ambiguous, or
   * its role breaks: fails closed, never throws for stale data.
   */
  resolve(name: string, at: string): ResolvedRole;
  /** What a stored role resolves to, or why it gives nothing. Its references are read at its home. */
  resolveStored(role: StoredRole): ResolvedRole | RoleBreak;
}

/**
 * A {@link RoleReader} over `roles`. A stored role is visible at a place when its home, absent for
 * the root, covers that place and fits the catalog: a home that no longer fits makes the role
 * inert. Throws `ERR_AUTHZ_MALFORMED` for `roles` that is not a list of stored roles, and, once
 * a name is read, for a role of that name whose home is not canonical or whose entries do not
 * match their grammar. Results are memoized for the reader's life.
 */
export function roleReader(
  catalog: CompiledCatalog,
  roles: readonly StoredRole[] | undefined,
): RoleReader {
  const byName = indexRoles(roles);
  const memo = new Map<StoredRole, ResolvedRole | RoleBreak>();
  const visiting = new Set<StoredRole>();

  const visible = (name: string, at: string): StoredRole[] =>
    (byName.get(name) ?? []).filter((role) => {
      const home = assertKey(role.home ?? "/");
      return fits(catalog, home) && covers(home, at);
    });

  const pick = (name: string, at: string): ResolvedRole | StoredRole | "none" | "ambiguous" => {
    const preset = catalog.presets.get(name);
    if (preset) return preset;
    const [first, ...others] = visible(name, at);
    if (!first) return "none";
    const signature = signatureOf(first);
    return others.every((role) => signatureOf(role) === signature) ? first : "ambiguous";
  };

  const resolveStored = (role: StoredRole): ResolvedRole | RoleBreak => {
    const known = memo.get(role);
    if (known) return known;
    const entries = role.entries.map((entry) => {
      const parts = readEntry(entry);
      if (!parts)
        throw malformed("The role entry is not written in its one form.", {
          what: "entry",
          value: entry,
        });
      return parts;
    });
    const home = role.home ?? "/";
    visiting.add(role);
    const result = combineEntries(catalog, entries, (name) => {
      const target = pick(name, home);
      if (target === "none") return { reason: "reference", role: role.name, reference: name };
      if (target === "ambiguous") return { reason: "ambiguous", role: role.name, reference: name };
      if (!isStoredRole(target)) return target;
      if (visiting.has(target)) return { reason: "cycle", role: role.name, reference: name };
      return resolveStored(target);
    });
    visiting.delete(role);
    memo.set(role, result);
    return result;
  };

  return {
    exists: (name, at) => catalog.presets.has(name) || visible(name, at).length > 0,
    stored: (name, at) => {
      const target = pick(name, at);
      return typeof target === "object" && isStoredRole(target) ? target : undefined;
    },
    resolve: (name, at) => {
      const target = pick(name, at);
      if (typeof target === "string") return NO_ROLE;
      if (!isStoredRole(target)) return target;
      const result = resolveStored(target);
      return isBreak(result) ? NO_ROLE : result;
    },
    resolveStored,
  };
}

function indexRoles(roles: unknown): Map<string, StoredRole[]> {
  const byName = new Map<string, StoredRole[]>();
  if (roles === undefined) return byName;
  if (!Array.isArray(roles)) throw rolesError(roles);
  for (const role of roles) {
    if (!isStoredRoleShape(role)) throw rolesError(role);
    const list = byName.get(role.name);
    if (list) list.push(role);
    else byName.set(role.name, [role]);
  }
  return byName;
}

function isStoredRoleShape(value: unknown): value is StoredRole {
  if (!isRecord(value)) return false;
  const { name, home, entries } = value;
  return (
    typeof name === "string" &&
    (home === undefined || typeof home === "string") &&
    Array.isArray(entries) &&
    entries.every((entry) => typeof entry === "string")
  );
}

function isStoredRole(value: ResolvedRole | StoredRole): value is StoredRole {
  return "entries" in value;
}

function signatureOf(role: StoredRole): string {
  return JSON.stringify([role.home ?? "/", [...new Set(role.entries)].toSorted(compareBytes)]);
}

function rolesError(value: unknown) {
  return malformed("The stored roles are not in their one form.", { what: "roles", value });
}
