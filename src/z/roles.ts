import { compiledOf } from "./_internal/compile.ts";
import { roleInvalid } from "./_internal/errors.ts";
import { sortedUnique } from "./_internal/grammar.ts";
import { roleReader } from "./_internal/roles.ts";
import { checkPlace } from "./_internal/structure.ts";
import type { Catalog } from "./catalog.ts";
import type { StoredRole } from "./types.ts";

/** Options of {@link resolveRole}. */
export interface ResolveRoleOptions {
  /** The place the name is read at, which picks among stored roles of one name. @default "/" */
  at?: string;
  roles?: readonly StoredRole[];
}

/**
 * The permissions a preset or a stored role gives, wildcards expanded and exclusions applied.
 *
 * @throws `ERR_AUTHZ_ROLE_INVALID` for a name that is neither.
 */
export function resolveRole<TPermission extends string>(
  catalog: Catalog<TPermission>,
  name: string,
  options?: ResolveRoleOptions,
): TPermission[] {
  const compiled = compiledOf(catalog);
  const at = checkPlace(compiled, options?.at);
  const reader = roleReader(compiled, options?.roles);
  if (typeof name !== "string" || !reader.exists(name, at)) {
    throw roleInvalid("The role is not defined at this place.", {
      role: name,
      reason: "unknown",
    });
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a role gives only permissions the catalog declares
  return sortedUnique(reader.resolve(name, at).gives) as TPermission[];
}
