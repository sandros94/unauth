import { compiledOf } from "./_internal/compile.ts";
import { errorOf } from "./_internal/issues/issue.ts";
import { roleIssues } from "./_internal/issues/role.ts";
import { indexRoles, roleReader } from "./_internal/roles.ts";
import { statementIssues } from "./_internal/issues/statement.ts";
import { clockSeconds } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type { Statement, StoredRole, ValidationIssue } from "./types.ts";

/** Options of {@link validateStatement} and {@link assertStatement}. */
export interface ValidateStatementOptions {
  /** The stored roles an assignment may name. Omit without stored roles. */
  roles?: readonly StoredRole[];
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
}

/** Options of {@link validateRole} and {@link assertRole}. */
export interface ValidateRoleOptions {
  /** The stored roles the role may reference, with every role they reference. Omit without stored roles. */
  roles?: readonly StoredRole[];
}

/**
 * Every problem of a statement before the application writes it, against the catalog, `roles` and
 * the time: an empty list when it is valid. Each issue names the member it is about, for a form to
 * show it there, and carries what {@link assertStatement} throws for it. All independent problems
 * are reported at once, in order: form, then an unknown permission or role, then a place that does
 * not fit, then an end already past. It asks nothing of who writes: whether the writer may is a
 * question of the application's own, asked of the statements first.
 *
 * Issues: `ERR_AUTHZ_MALFORMED` for a value that is not a statement or a member not in its one form
 * (`statement`), a place that is not canonical (`place`), an end that is not a time (`time`);
 * `ERR_AUTHZ_PERMISSION_UNKNOWN` for a permission or a pattern that names no permission of the
 * catalog; `ERR_AUTHZ_ROLE_INVALID` (`unknown`) for an assignment of a role that is neither a
 * preset nor among `roles`; `ERR_AUTHZ_PLACE_OUTSIDE` for a place that does not fit the structure;
 * `ERR_AUTHZ_STATEMENT_ENDED` for an `expiresAt` that is not later than the clock.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for `roles` that are not stored roles (`roles`) and a clock that
 * does not read a time (`time`), `ERR_AUTHZ_ROLE_INVALID` (`duplicate`) for two stored roles of
 * one name: no member of the statement can fix those.
 *
 * @example
 * const issues = validateStatement(catalog, body, { roles });
 * if (issues.length > 0) return { status: 422, issues };
 */
export function validateStatement(
  catalog: Catalog,
  value: unknown,
  options?: ValidateStatementOptions,
): ValidationIssue[] {
  const compiled = compiledOf(catalog);
  const time = clockSeconds(options);
  const roles = roleReader(compiled, options?.roles);
  return statementIssues(compiled, roles, value, time);
}

/**
 * Checks a statement as {@link validateStatement} does, and types it: throws the first issue as the
 * `UnauthError` it stands for, with its code, message, cause and status 400.
 *
 * @throws the first issue, and what {@link validateStatement} throws.
 *
 * @example
 * const { allowed } = ask(catalog, await readFor(author), { permission: "access:manage", place });
 * if (!allowed) throw forbidden();
 * assertStatement(catalog, body, { roles });
 * await db.insert(statementsTable).values(body).onConflictDoUpdate(sameIdentity);
 */
export function assertStatement(
  catalog: Catalog,
  value: unknown,
  options?: ValidateStatementOptions,
): asserts value is Statement {
  const [issue] = validateStatement(catalog, value, options);
  if (issue) throw errorOf(issue);
}

/**
 * Every problem of a stored role before the application writes it, against the catalog and the
 * stored roles it may reference: an empty list when it is valid. Each issue names the member it is
 * about, `["entries", index]` for an entry, and carries what {@link assertRole} throws for it. A
 * role of the same name among `roles` is the one being edited, and is read as replaced. The name of
 * a preset is not refused, though a preset wins wherever the name is read.
 *
 * Issues: `ERR_AUTHZ_MALFORMED` for a value that is not a stored role or a name that is not a
 * token (`role`), an entry not in its one form (`entry`); `ERR_AUTHZ_PERMISSION_UNKNOWN` for an
 * entry that names an unknown permission, or a pattern that matches none;
 * `ERR_AUTHZ_ROLE_INVALID` for a reference, with or without `-`, to a role that is neither a
 * preset nor among `roles`, directly or through the stored roles referenced (`reference`), and for
 * references that loop (`cycle`).
 *
 * @throws `ERR_AUTHZ_MALFORMED` for `roles` that are not stored roles (`roles`), or one whose
 * entries a reference reaches not in their one form (`entry`), and `ERR_AUTHZ_ROLE_INVALID`
 * (`duplicate`) for two stored roles of one name.
 *
 * @example
 * const issues = validateRole(catalog, { name: "desk", entries: ["viewer", "-report:write"] }, { roles });
 */
export function validateRole(
  catalog: Catalog,
  value: unknown,
  options?: ValidateRoleOptions,
): ValidationIssue[] {
  const compiled = compiledOf(catalog);
  return roleIssues(compiled, value, indexRoles(options?.roles));
}

/**
 * Checks a stored role as {@link validateRole} does, and types it: throws the first issue as the
 * `UnauthError` it stands for, with its code, message, cause and status 400.
 *
 * @throws the first issue, and what {@link validateRole} throws.
 *
 * @example
 * assertRole(catalog, body, { roles });
 * await db.insert(rolesTable).values(body).onConflictDoUpdate(sameName);
 */
export function assertRole(
  catalog: Catalog,
  value: unknown,
  options?: ValidateRoleOptions,
): asserts value is StoredRole {
  const [issue] = validateRole(catalog, value, options);
  if (issue) throw errorOf(issue);
}
