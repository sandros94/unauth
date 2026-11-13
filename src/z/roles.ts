import { compiledOf } from "./_internal/compile.ts";
import { roleInvalid } from "./_internal/errors.ts";
import { sortedUnique } from "./_internal/grammar.ts";
import { roleReader } from "./_internal/roles.ts";
import type { Catalog } from "./catalog.ts";
import type { StoredRole } from "./types.ts";

/** Options of {@link resolveRole}. */
export interface ResolveRoleOptions {
  /** The stored roles the name may be, with every role they reference. Omit without stored roles. */
  roles?: readonly StoredRole[];
}

/**
 * The permissions a preset or a stored role gives, wildcards expanded and exclusions applied. A
 * name that is both reads as the preset. A stored role that references a role neither a preset
 * nor handed in, or sits on a cycle of references or references one, gives nothing.
 *
 * @throws `ERR_AUTHZ_ROLE_INVALID` (`unknown`) for a name that is neither a preset nor a stored
 * role handed in, (`duplicate`) for two stored roles of one name.
 * @throws `ERR_AUTHZ_MALFORMED` for `roles` that are not stored roles, and for an entry of a role
 * read that is not in its one form.
 *
 * @example
 * const gives = resolveRole(catalog, "desk", { roles: await db.select().from(rolesTable) });
 */
export function resolveRole<TPermission extends string>(
  catalog: Catalog<TPermission>,
  name: string,
  options?: ResolveRoleOptions,
): TPermission[] {
  const reader = roleReader(compiledOf(catalog), options?.roles);
  if (typeof name !== "string" || !reader.exists(name)) {
    throw roleInvalid("The role is neither a preset nor a stored role handed in.", {
      role: name,
      reason: "unknown",
    });
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a role gives only permissions the catalog declares
  return sortedUnique(reader.resolve(name).gives) as TPermission[];
}
