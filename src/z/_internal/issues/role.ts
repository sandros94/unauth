import { isRecord } from "../../../_internal/shared.ts";
import type { UnauthError } from "../../../error.ts";
import type { StoredRole, ValidationIssue } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import { malformed, permissionUnknown, roleInvalid } from "../errors.ts";
import { isToken, readEntry } from "../grammar.ts";
import { issueOf } from "./issue.ts";
import { expand } from "../permissions.ts";
import { entryMalformed, isBreak, roleReader } from "../roles.ts";

/**
 * Every problem of a stored role being validated against the catalog and `roles`, the stored roles
 * it may reference, as the model's validation refuses it: its form first, the name then each
 * entry, then, entry by entry, an unknown permission, a reference to a role that is neither a
 * preset nor among `roles`, directly or through the roles referenced, and a cycle. A role of the
 * same name among `roles` is the one being edited, read as replaced. A name that is not a token
 * can be referenced by no role, so its references are followed as those of a role nobody names.
 */
export function roleIssues(
  catalog: CompiledCatalog,
  role: unknown,
  roles: readonly StoredRole[],
): ValidationIssue[] {
  if (!isRecord(role)) return [issueOf(shapeError(role), [])];
  const { name, entries } = role;
  const form: ValidationIssue[] = [];
  const found: ValidationIssue[] = [];
  if (!isToken(name)) {
    const error = malformed("The role's name is not a token.", { what: "role", value: name });
    form.push(issueOf(error, ["name"]));
  }
  if (!Array.isArray(entries)) return [...form, issueOf(shapeError(role), ["entries"])];
  const refer = referenceCheck(catalog, name, roles);
  for (const [index, entry] of entries.entries()) {
    const parts = readEntry(entry);
    const path = ["entries", index];
    if (!parts) {
      form.push(issueOf(entryMalformed(entry), path));
    } else if (parts.kind === "pattern") {
      if (expand(catalog, parts.name).size === 0) {
        found.push(issueOf(permissionUnknown(parts.name), path));
      }
    } else {
      const broken = refer(parts.name);
      if (broken) found.push(issueOf(broken, path));
    }
  }
  return [...form, ...found];
}

/**
 * Why a reference of the role `name` to `reference` makes it give nothing, `undefined` when it
 * does not. The roles it may reach are `roles` without the one it replaces, and in its place a role
 * that references itself, so that reaching `name` again reads as the cycle it is.
 */
function referenceCheck(
  catalog: CompiledCatalog,
  name: unknown,
  roles: readonly StoredRole[],
): (reference: string) => UnauthError<"ERR_AUTHZ_ROLE_INVALID"> | undefined {
  const own = isToken(name) ? name : unusedName(catalog, roles);
  const role = typeof name === "string" ? name : "";
  const others = roles.filter((other) => other.name !== own);
  const reader = roleReader(catalog, [...others, { name: own, entries: [own] }]);
  return (reference) => {
    const result = reader.resolveStored({ name: own, entries: [reference] });
    if (!isBreak(result)) return undefined;
    const message =
      result.reason === "cycle"
        ? "The role's references form a cycle."
        : "The role references a role that is neither a preset nor a stored role.";
    return roleInvalid(message, { role, reason: result.reason, reference: result.reference });
  };
}

function unusedName(catalog: CompiledCatalog, roles: readonly StoredRole[]): string {
  const taken = new Set(roles.map((other) => other.name));
  let candidate = "x";
  while (taken.has(candidate) || catalog.presets.has(candidate)) candidate += "x";
  return candidate;
}

function shapeError(value: unknown) {
  return malformed("The role is not in its shape.", { what: "role", value });
}
