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
 * What a walk answers for a name an entry references: the role it resolves to, the break that makes
 * the holder give nothing, or a definition to resolve first.
 */
export type Referred<TNode> = ResolvedRole | RoleBreak | { readonly descend: TNode };

/**
 * How {@link walkRoles} reads definitions. `open` reads a definition's entries when its
 * resolution starts, `refer` answers for a name one of them references, `close` receives what a
 * definition resolved to, a break included, once it is done.
 */
export interface RoleWalk<TNode> {
  open(node: TNode): readonly EntryParts[];
  refer(name: string, holder: TNode): Referred<TNode>;
  close(node: TNode, result: ResolvedRole | RoleBreak): void;
}

/**
 * Resolves `root` to `gives` and `withholds`, wildcards expanded against the catalog: what the
 * referenced roles give, less what they withhold that the entries do not name themselves, plus
 * what the entries include, less what they exclude. An exclusion of a permission reaches every
 * permission that implies it, and an unknown permission is inert. Entries are read in order, and a
 * definition `refer` descends into is resolved before the next entry, on an explicit stack, so no
 * depth of references exhausts the call stack. The first break met ends the holder, and every role
 * waiting on it, with that same break.
 */
export function walkRoles<TNode>(
  catalog: CompiledCatalog,
  root: TNode,
  walk: RoleWalk<TNode>,
): ResolvedRole | RoleBreak {
  const parents: RoleFrame<TNode>[] = [];
  let frame = frameOf(root, walk.open(root));
  let returned: ResolvedRole | RoleBreak | undefined;
  for (;;) {
    let result: ResolvedRole | RoleBreak | undefined;
    if (returned !== undefined && frame.pending) {
      if (isBreak(returned)) result = returned;
      else addRole(catalog, frame, frame.pending, returned);
    }
    returned = undefined;
    let child: TNode | undefined;
    while (result === undefined && child === undefined) {
      const entry = frame.entries[frame.index];
      if (entry === undefined) {
        result = combined(frame);
        break;
      }
      frame.index++;
      if (entry.kind === "pattern") {
        addPattern(catalog, frame, entry);
        continue;
      }
      const referred = walk.refer(entry.name, frame.node);
      if ("descend" in referred) {
        frame.pending = entry;
        child = referred.descend;
      } else if (isBreak(referred)) result = referred;
      else addRole(catalog, frame, entry, referred);
    }
    if (child !== undefined) {
      parents.push(frame);
      frame = frameOf(child, walk.open(child));
      continue;
    }
    if (result === undefined) continue;
    walk.close(frame.node, result);
    const parent = parents.pop();
    if (!parent) return result;
    frame = parent;
    returned = result;
  }
}

/** Whether a resolution broke instead of resolving. */
export function isBreak(value: ResolvedRole | RoleBreak): value is RoleBreak {
  return "reason" in value;
}

/** Reads role names against a source of definitions, failing closed. */
export interface RoleReader {
  /** Whether `name` names a role of the source. */
  exists(name: string): boolean;
  /**
   * What `name` gives. {@link NO_ROLE} when the source has no role of that name, or its role
   * breaks: fails closed, never throws for stale data.
   */
  resolve(name: string): ResolvedRole;
  /** What a stored role resolves to, or why it gives nothing. */
  resolveStored(role: StoredRole): ResolvedRole | RoleBreak;
}

/**
 * Where a reader finds a role by name: one resolved already, a preset of the catalog, or a
 * definition it resolves itself. `undefined` for a role that does not exist.
 */
export type RoleSource = (name: string) => ResolvedRole | StoredRole | undefined;

/**
 * A {@link RoleReader} over the presets and the stored roles handed in. A name that is both a
 * preset and a stored role reads as the preset. Throws `ERR_AUTHZ_MALFORMED` for `roles` that is
 * not a list of stored roles, and, once a name is read, for a role of that name whose entries do
 * not match their grammar. `ERR_AUTHZ_ROLE_INVALID` (`duplicate`) for two stored roles of one
 * name.
 */
export function roleReader(catalog: CompiledCatalog, roles: unknown): RoleReader {
  const byName = indexRoles(roles);
  return readerOver(catalog, (name) => catalog.presets.get(name) ?? byName.get(name));
}

/**
 * A {@link RoleReader} over `find`, the procedure of the model's role resolution on the catalog
 * in force. A reference that `find` does not know breaks the role, and so does one met again while
 * it is being resolved, so every role on a cycle and every role referencing one gives nothing.
 * Throws `ERR_AUTHZ_MALFORMED` once a definition whose entries do not match their grammar is read.
 * Results are memoized for the reader's life.
 */
export function readerOver(catalog: CompiledCatalog, find: RoleSource): RoleReader {
  const memo = new Map<StoredRole, ResolvedRole | RoleBreak>();
  const visiting = new Set<StoredRole>();

  const walk: RoleWalk<StoredRole> = {
    open: (role) => {
      const entries = role.entries.map((entry) => {
        const parts = readEntry(entry);
        if (!parts) throw entryMalformed(entry);
        return parts;
      });
      visiting.add(role);
      return entries;
    },
    refer: (name, holder) => {
      const found = find(name);
      if (!found) return { reason: "reference", role: holder.name, reference: name };
      if (isResolved(found)) return found;
      if (visiting.has(found)) return { reason: "cycle", role: holder.name, reference: name };
      return memo.get(found) ?? { descend: found };
    },
    close: (role, result) => {
      visiting.delete(role);
      memo.set(role, result);
    },
  };
  const resolveStored = (role: StoredRole): ResolvedRole | RoleBreak =>
    memo.get(role) ?? walkRoles(catalog, role, walk);

  return {
    exists: (name) => find(name) !== undefined,
    resolve: (name) => {
      const found = find(name);
      if (!found) return NO_ROLE;
      if (isResolved(found)) return found;
      const result = resolveStored(found);
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

/**
 * The stored roles handed in, by name. `ERR_AUTHZ_MALFORMED` (`roles`) for a value that is not a
 * list of stored roles, `ERR_AUTHZ_ROLE_INVALID` (`duplicate`) for two of one name. Entries are
 * read where a role is.
 */
export function indexRoles(roles: unknown): Map<string, StoredRole> {
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

interface RoleFrame<TNode> {
  readonly node: TNode;
  readonly entries: readonly EntryParts[];
  index: number;
  pending: EntryParts | undefined;
  readonly includes: Set<string>;
  readonly excludes: Set<string>;
  readonly inherited: Set<string>;
  readonly forbidden: Set<string>;
}

function frameOf<TNode>(node: TNode, entries: readonly EntryParts[]): RoleFrame<TNode> {
  return {
    node,
    entries,
    index: 0,
    pending: undefined,
    includes: new Set(),
    excludes: new Set(),
    inherited: new Set(),
    forbidden: new Set(),
  };
}

function addPattern(catalog: CompiledCatalog, frame: RoleFrame<unknown>, entry: EntryParts): void {
  const set = entry.exclude ? removed(catalog, entry.name) : expand(catalog, entry.name);
  for (const permission of set) (entry.exclude ? frame.excludes : frame.includes).add(permission);
}

function addRole(
  catalog: CompiledCatalog,
  frame: RoleFrame<unknown>,
  entry: EntryParts,
  role: ResolvedRole,
): void {
  if (entry.exclude) {
    for (const permission of role.gives) {
      frame.excludes.add(permission);
      for (const above of implying(catalog, permission)) frame.excludes.add(above);
    }
  } else {
    for (const permission of role.gives) frame.inherited.add(permission);
    for (const permission of role.withholds) frame.forbidden.add(permission);
  }
}

function combined(frame: RoleFrame<unknown>): ResolvedRole {
  const { includes, excludes, inherited, forbidden } = frame;
  const gives = new Set<string>(includes);
  for (const permission of inherited) if (!forbidden.has(permission)) gives.add(permission);
  for (const permission of excludes) gives.delete(permission);
  const withholds = new Set<string>(excludes);
  for (const permission of forbidden) if (!includes.has(permission)) withholds.add(permission);
  return { gives, withholds };
}

function isResolved(value: ResolvedRole | StoredRole): value is ResolvedRole {
  return "gives" in value;
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
