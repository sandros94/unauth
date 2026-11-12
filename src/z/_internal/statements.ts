import { isRecord } from "../../_internal/shared.ts";
import type { UnauthError } from "../../error.ts";
import type { Statement, StatementKind } from "../types.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { malformed } from "./errors.ts";
import { isPattern, isToken } from "./grammar.ts";
import { assertKey } from "./keys.ts";
import { expand } from "./permissions.ts";
import { fits } from "./structure.ts";
import { assertTime } from "./time.ts";

/**
 * A statement as the engine reads it: `place` is always a canonical key, `"/"` for the root, and
 * `source` is the object handed in, for a decision to name. One that {@link readStatement}
 * returns also fits the catalog and names a declared permission.
 */
export interface ReadStatement {
  readonly kind: StatementKind;
  readonly subject: string;
  /** A pattern, or a role name for `assign`. */
  readonly value: string;
  readonly place: string;
  /** The second it ends, `undefined` when permanent. */
  readonly expiresAt: number | undefined;
  readonly source: Statement;
}

/**
 * Reads one statement handed in. `undefined` when it is well formed but inert: an allow, a deny or
 * an exclusion whose pattern expands to no declared permission, or a place that does not fit the
 * catalog. An assignment is never inert here: whether its role exists is read with the roles.
 *
 * @throws what {@link readWellFormed} throws.
 */
export function readStatement(
  catalog: CompiledCatalog,
  statement: unknown,
): ReadStatement | undefined {
  const read = readWellFormed(statement);
  if (!fits(catalog, read.place)) return undefined;
  const { kind, value } = read;
  if (kind !== "assign" && value !== "*" && expand(catalog, value).size === 0) return undefined;
  return read;
}

/**
 * The members of what the application read for a subject, the subject checked. `statements` and
 * `roles` are left to {@link readStatements} and the role reader.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a read that is not an object (`statement`), and a subject that
 * is not a non-empty string (`subject`).
 */
export function readSubjectStatements(read: unknown): {
  subject: string;
  statements: unknown;
  roles: unknown;
} {
  if (!isRecord(read)) throw statementMalformed(read);
  const { subject, statements, roles } = read;
  if (!isFilled(subject)) {
    throw malformed("The subject is not an identifier.", { what: "subject", value: subject });
  }
  return { subject, statements, roles };
}

/**
 * Reads every statement handed in, in order, inert ones left out. Ended statements and statements
 * at any place are kept: each use filters by its own chain and time.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`statement`) for `statements` that is not a list, and what
 * {@link readStatement} throws for any of its items.
 */
export function readStatements(catalog: CompiledCatalog, statements: unknown): ReadStatement[] {
  if (!Array.isArray(statements)) throw statementMalformed(statements);
  const out: ReadStatement[] = [];
  for (const statement of statements) {
    const read = readStatement(catalog, statement);
    if (read) out.push(read);
  }
  return out;
}

/** Whether `value` is one of the four kinds of statement. */
export function isKind(value: unknown): value is StatementKind {
  return typeof value === "string" && KINDS.has(value);
}

/** Whether `value` is a non-empty string. */
export function isFilled(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

/** `ERR_AUTHZ_MALFORMED` (`statement`) for a statement, or a list of them, not in its shape. */
export function statementMalformed(value: unknown): UnauthError<"ERR_AUTHZ_MALFORMED"> {
  return malformed("The statement is not in its shape.", { what: "statement", value });
}

const KINDS: ReadonlySet<string> = new Set<StatementKind>(["allow", "assign", "deny", "exclude"]);

/**
 * Reads one statement for its form alone, whatever the catalog holds.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a statement not in its shape (`statement`): not an object, an
 * unknown kind, a subject or a value that is not a non-empty string, a value of an allow, a deny or
 * an exclusion that is not a pattern, a value of an assignment that is not a role name. A place
 * that is not a canonical key is `place`, an `expiresAt` that is not a time is `time`.
 */
function readWellFormed(statement: unknown): ReadStatement {
  if (!isRecord(statement)) throw statementMalformed(statement);
  const { kind, subject, value, place, expiresAt } = statement;
  if (!isKind(kind) || !isFilled(subject) || !isFilled(value)) throw statementMalformed(statement);
  if (kind === "assign" ? !isToken(value) : !isPattern(value)) throw statementMalformed(statement);
  return {
    kind,
    subject,
    value,
    place: place === undefined ? "/" : assertKey(place),
    expiresAt: expiresAt === undefined ? undefined : assertTime(expiresAt),
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- every member the type names was checked above
    source: statement as unknown as Statement,
  };
}
