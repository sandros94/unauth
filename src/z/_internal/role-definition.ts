import { isRecord } from "../../_internal/shared.ts";
import type { StoredRole } from "../types.ts";
import type { CompiledCatalog, ResolvedRole } from "./compiled.ts";
import { malformed, roleInvalid } from "./errors.ts";
import { isToken, readEntry } from "./grammar.ts";
import { assertKey, covers } from "./keys.ts";
import { assertPattern } from "./permissions.ts";
import { isBreak, roleReader } from "./roles.ts";
import { checkPlace, fits } from "./structure.ts";

/** Options of {@link checkRoleDefinition}. */
export interface RoleDefinitionOptions {
  /**
   * The stored roles of every name the role references, whatever their home, and every stored role
   * of its own name, the one being edited included.
   */
  roles?: readonly StoredRole[];
}

/**
 * Checks the definition or the edit of a stored role against the rules on stored roles, and
 * returns what it resolves to once written, for the check on what its author holds. The role of
 * the same name and home in `roles`, when there is one, is the one being edited and is replaced.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a role not in its shape, a name that is not a token, a home
 * that is not canonical, or an entry that does not match its grammar.
 * @throws `ERR_AUTHZ_PLACE_OUTSIDE` for a home that does not fit the catalog.
 * @throws `ERR_AUTHZ_PERMISSION_UNKNOWN` for an entry naming a permission, or a wildcard matching
 * none, the catalog does not declare.
 * @throws `ERR_AUTHZ_ROLE_INVALID` for the name of a preset (`preset`), the name of a stored role
 * whose home is on the same chain (`taken`), and a reference, direct or through the roles
 * referenced, to a role unknown at the home of the role holding it, which also refuses a role
 * whose home is narrower (`reference`), to a name two stored roles share there (`ambiguous`), or
 * that loops (`cycle`).
 */
export function checkRoleDefinition(
  catalog: CompiledCatalog,
  role: unknown,
  options?: RoleDefinitionOptions,
): ResolvedRole {
  if (!isRecord(role))
    throw malformed("The role is not in its shape.", { what: "role", value: role });
  const { name, home: givenHome, entries } = role;
  if (!isToken(name))
    throw malformed("The role's name is not a token.", { what: "role", value: name });
  if (!Array.isArray(entries)) {
    throw malformed("The role is not in its shape.", { what: "role", value: role });
  }
  const home = checkPlace(catalog, givenHome);
  if (catalog.presets.has(name)) {
    throw roleInvalid("The name is a preset's.", { role: name, reason: "preset" });
  }
  const own: string[] = [];
  for (const entry of entries) {
    const parts = readEntry(entry);
    if (!parts)
      throw malformed("The role entry is not written in its one form.", {
        what: "entry",
        value: entry,
      });
    if (parts.kind === "pattern") assertPattern(catalog, parts.name);
    own.push(`${parts.exclude ? "-" : ""}${parts.name}`);
  }

  const roles = options?.roles ?? [];
  if (!Array.isArray(roles)) {
    throw malformed("The stored roles are not in their one form.", { what: "roles", value: roles });
  }
  const others: StoredRole[] = [];
  for (const other of roles) {
    if (isRecord(other) && other.name === name) {
      const otherHome = assertKey(other.home ?? "/");
      if (otherHome === home) continue;
      if (fits(catalog, otherHome) && (covers(otherHome, home) || covers(home, otherHome))) {
        throw roleInvalid("A stored role of that name is defined along the same places.", {
          role: name,
          reason: "taken",
        });
      }
    }
    others.push(other);
  }
  const defined: StoredRole = { name, home, entries: own };
  const result = roleReader(catalog, [...others, defined]).resolveStored(defined);
  if (isBreak(result)) {
    throw roleInvalid(
      result.reason === "cycle"
        ? "The role's references form a cycle."
        : "The role references a role that is not available at its home.",
      { role: name, reason: result.reason, reference: result.reference },
    );
  }
  return result;
}
