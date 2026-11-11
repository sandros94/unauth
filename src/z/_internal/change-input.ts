import { isRecord } from "../../_internal/shared.ts";
import type { StoredRole } from "../types.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { malformed, roleInvalid } from "./errors.ts";
import { assertPattern } from "./permissions.ts";
import { readAsker } from "./question.ts";
import { checkRoleDefinition } from "./role-definition.ts";
import type { RoleReader } from "./roles.ts";
import { type ReadStatement, readStatement } from "./statements.ts";
import { checkPlace, fits } from "./structure.ts";

/** Who asks for a change: its own identifier and every group it belongs to. */
export interface Author {
  readonly subject: string;
  readonly groups: readonly string[];
}

/**
 * A change checked for what it is, before any rule: a statement placed, valid against the
 * catalog; a statement removed, well formed, `inert` when its place no longer fits the catalog;
 * a stored role defined, with its home and what it gives once written.
 */
export type ReadChange =
  | { readonly action: "place"; readonly statement: ReadStatement }
  | { readonly action: "remove"; readonly statement: ReadStatement; readonly inert: boolean }
  | { readonly action: "define"; readonly home: string; readonly gives: ReadonlySet<string> };

/**
 * The author of a change from its options.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`question`) for options that are not an object, an `author` that is
 * not a non-empty string, or `groups` that are not a list of strings.
 */
export function readAuthor(options: unknown): Author {
  if (!isRecord(options)) {
    throw malformed("The change's options are not in their shape.", {
      what: "question",
      value: options,
    });
  }
  const { subject, groups } = readAsker({ subject: options.author, groups: options.groups });
  return { subject, groups };
}

/**
 * Checks what a change is before any rule asks who may make it. A statement removed is checked
 * for its shape and its key only, so that what has gone inert since it was written stays
 * removable.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`statement`) for a change that is not an object or names another
 * action, and what `readStatement` throws for the statement.
 * @throws `ERR_AUTHZ_PERMISSION_UNKNOWN`, `ERR_AUTHZ_PLACE_OUTSIDE` for a statement placed that
 * names a permission or a place the catalog does not hold, `ERR_AUTHZ_ROLE_INVALID` (`unknown`)
 * for one assigning a role that does not exist at its place.
 * @throws what `checkRoleDefinition` throws for a role defined.
 */
export function readChange(
  catalog: CompiledCatalog,
  change: unknown,
  roles: { reader: RoleReader; given: readonly StoredRole[] | undefined },
): ReadChange {
  if (!isRecord(change) || !isAction(change.action)) {
    throw malformed("The change is not in its shape.", { what: "statement", value: change });
  }
  if (change.action === "define") {
    const { gives } = checkRoleDefinition(catalog, change.role, { roles: roles.given });
    const home = checkPlace(catalog, isRecord(change.role) ? change.role.home : undefined);
    return { action: "define", home, gives };
  }
  const statement = readWellFormed(catalog, change.statement);
  if (change.action === "remove") {
    return { action: "remove", statement, inert: !fits(catalog, statement.place) };
  }
  if (statement.kind !== "assign") assertPattern(catalog, statement.value);
  checkPlace(catalog, statement.place);
  if (statement.kind === "assign" && !roles.reader.exists(statement.value, statement.place)) {
    throw roleInvalid("The role is not defined at this place.", {
      role: statement.value,
      reason: "unknown",
    });
  }
  return { action: "place", statement };
}

const ACTIONS: ReadonlySet<unknown> = new Set(["place", "remove", "define"]);

function isAction(value: unknown): value is "place" | "remove" | "define" {
  return ACTIONS.has(value);
}

function readWellFormed(catalog: CompiledCatalog, statement: unknown): ReadStatement {
  const read = readStatement(catalog, statement);
  if (read) return read;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- readStatement checked every member and only found it inert
  const { kind, subject, value, place, expiresAt } = statement as ReadStatement["source"];
  return {
    kind,
    subject,
    value,
    place: place ?? "/",
    expiresAt,
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- as above
    source: statement as ReadStatement["source"],
  };
}
