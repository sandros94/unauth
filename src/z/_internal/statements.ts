import { isRecord } from "../../_internal/shared.ts";
import type { Statement, StatementIdentity, StatementKind } from "../types.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { malformed } from "./errors.ts";
import { isPattern, isToken } from "./grammar.ts";
import { assertKey } from "./keys.ts";
import { expand } from "./permissions.ts";
import { fits } from "./structure.ts";
import { assertTime } from "./time.ts";

/**
 * A statement as the engine reads it: `place` is always a canonical key that fits the catalog,
 * `"/"` for the root, and `source` is the object handed in, for a decision to name.
 */
export interface ReadStatement {
  readonly kind: StatementKind;
  readonly subject: string;
  /** A pattern that expands to at least one declared permission, or a role name for `assign`. */
  readonly value: string;
  readonly place: string;
  /** The second it ends, `undefined` when permanent. */
  readonly expiresAt: number | undefined;
  readonly source: Statement;
}

/**
 * Reads one statement handed in. `undefined` when it is well formed but inert: an allow, a deny or
 * an exclusion whose pattern expands to no declared permission, or a place that does not fit the
 * catalog. An assignment is never inert here, since only its place says whether its role exists.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a statement not in its shape (`statement`): not an object, an
 * unknown kind, a subject or a value that is not a non-empty string, a value of an allow, a deny or
 * an exclusion that is not a pattern, a value of an assignment that is not a role name. A place
 * that is not a canonical key is `place`, an `expiresAt` that is not a time is `time`.
 */
export function readStatement(
  catalog: CompiledCatalog,
  statement: unknown,
): ReadStatement | undefined {
  if (!isRecord(statement)) throw shapeError(statement);
  const { kind, subject, value, place, expiresAt } = statement;
  if (!isKind(kind) || !isFilled(subject) || !isFilled(value)) throw shapeError(statement);
  if (kind === "assign" ? !isToken(value) : !isPattern(value)) throw shapeError(statement);
  const key = place === undefined ? "/" : assertKey(place);
  const end = expiresAt === undefined ? undefined : assertTime(expiresAt);
  if (!fits(catalog, key)) return undefined;
  if (kind !== "assign" && value !== "*" && expand(catalog, value).size === 0) return undefined;
  return {
    kind,
    subject,
    value,
    place: key,
    expiresAt: end,
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- every member the type names was checked above
    source: statement as unknown as Statement,
  };
}

/**
 * Reads every statement handed in, in order, inert ones left out. Ended statements and statements
 * about any subject at any place are kept: each use filters by its own identifiers, chain and time.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`statement`) for `statements` that is not a list, and what
 * {@link readStatement} throws for any of its items.
 */
export function readStatements(catalog: CompiledCatalog, statements: unknown): ReadStatement[] {
  if (!Array.isArray(statements)) throw shapeError(statements);
  const out: ReadStatement[] = [];
  for (const statement of statements) {
    const read = readStatement(catalog, statement);
    if (read) out.push(read);
  }
  return out;
}

/**
 * The identity of a statement as one string: equal for two statements exactly when their kind,
 * subject, value and place are, an absent place and `"/"` alike. Expects a well-formed statement.
 */
export function identityOf(statement: StatementIdentity | ReadStatement): string {
  return JSON.stringify([
    statement.kind,
    statement.subject,
    statement.value,
    statement.place ?? "/",
  ]);
}

/** Whether a statement is a permanent management: a permanent allow of `*` at the root. */
export function isPermanentManagement(statement: ReadStatement): boolean {
  return (
    statement.kind === "allow" &&
    statement.value === "*" &&
    statement.place === "/" &&
    statement.expiresAt === undefined
  );
}

/**
 * The permanent management about `subject` or one of `groups` that makes it a permanent manager,
 * the first in `statements`, or `undefined` when it is none.
 */
export function permanentManagementOf(
  statements: readonly ReadStatement[],
  identity: { subject: string; groups: readonly string[] },
): ReadStatement | undefined {
  const { subject, groups } = identity;
  return statements.find(
    (statement) =>
      isPermanentManagement(statement) &&
      (statement.subject === subject || groups.includes(statement.subject)),
  );
}

/** Whether `subject` with `groups` is a permanent manager given `statements`. */
export function isPermanentManager(
  statements: readonly ReadStatement[],
  identity: { subject: string; groups: readonly string[] },
): boolean {
  return permanentManagementOf(statements, identity) !== undefined;
}

const KINDS: ReadonlySet<string> = new Set<StatementKind>(["allow", "assign", "deny", "exclude"]);

function isKind(value: unknown): value is StatementKind {
  return typeof value === "string" && KINDS.has(value);
}

function isFilled(value: unknown): value is string {
  return typeof value === "string" && value !== "";
}

function shapeError(value: unknown) {
  return malformed("The statement is not in its shape.", { what: "statement", value });
}
