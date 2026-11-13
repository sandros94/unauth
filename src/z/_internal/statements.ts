import { isRecord } from "../../_internal/shared.ts";
import type { UnauthError } from "../../error.ts";
import type { Statement, StatementKind } from "../types.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { malformed } from "./errors.ts";
import { isPattern, isToken } from "./grammar.ts";
import { assertKey, chainOf } from "./keys.ts";
import { blocking, down, isSpellingOf, wanted } from "./permissions.ts";
import { assertTime } from "./time.ts";

/**
 * A statement as the engine reads it: `place` is always a canonical key, `"/"` for the root, and
 * `source` is the object handed in, for a decision to name.
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
 * The members of what the application read for a subject, the subject checked. `statements` and
 * `roles` are left to their readers.
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
 * Reads, in order, the statements handed in that a question about `permission` at `place` reads:
 * those at a key of the chain of `place`, an absent place being the root, compared byte by byte
 * and never parsed, and of those the assignments and the statements whose value is a spelling the
 * question looks up for their kind: what blocks the permission for a deny, what satisfies it for
 * an allow, what takes one of those out for an exclusion. Every other item is skipped unchecked,
 * whatever it holds. What is read is checked for its form, as {@link readWrittenStatements} checks
 * it.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`statement`) for `statements` that is not a list, and what
 * {@link readWellFormed} throws for a statement read.
 */
export function readAskedStatements(
  catalog: CompiledCatalog,
  statements: unknown,
  asked: { readonly permission: string; readonly place: string },
): ReadStatement[] {
  if (!Array.isArray(statements)) throw statementMalformed(statements);
  const list: readonly unknown[] = statements;
  const chain = new Set(chainOf(asked.place));
  const { permission } = asked;
  const looked: Record<StatementKind, ReadonlySet<string> | undefined> = {
    allow: wanted(catalog, permission),
    assign: undefined,
    deny: blocking(catalog, permission),
    exclude: down(catalog, permission),
  };
  const out: ReadStatement[] = [];
  for (const statement of list) {
    if (!isRecord(statement)) continue;
    const { kind, value, place = "/" } = statement;
    if (typeof place !== "string" || !chain.has(place)) continue;
    if (!isKind(kind)) continue;
    const permissions = looked[kind];
    if (permissions && !isSpellingOf(value, permissions)) continue;
    out.push(readWellFormed(statement, chain));
  }
  return out;
}

/**
 * Reads every statement handed in, in order, for its form alone: inert ones are kept as written,
 * for grants that a later catalog may read otherwise, and for a decision, to which they give,
 * remove and block nothing.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`statement`) for `statements` that is not a list, and what
 * {@link readWellFormed} throws for any of its items.
 */
export function readWrittenStatements(statements: unknown): ReadStatement[] {
  if (!Array.isArray(statements)) throw statementMalformed(statements);
  const canonical = new Set<string>();
  return statements.map((statement: unknown) => readWellFormed(statement, canonical));
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
 * Reads one statement for its form alone, whatever the catalog holds. `canonical` holds the keys
 * already found canonical, so that a place repeated across a list is checked once.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a statement not in its shape (`statement`): not an object, an
 * unknown kind, a subject or a value that is not a non-empty string, a value of an allow, a deny or
 * an exclusion that is not a pattern, a value of an assignment that is not a role name. A place
 * that is not a canonical key is `place`, an `expiresAt` that is not a time is `time`.
 */
function readWellFormed(statement: unknown, canonical = new Set<string>()): ReadStatement {
  if (!isRecord(statement)) throw statementMalformed(statement);
  const { kind, subject, value, place, expiresAt } = statement;
  if (!isKind(kind) || !isFilled(subject) || !isFilled(value)) throw statementMalformed(statement);
  if (kind === "assign" ? !isToken(value) : !isPattern(value)) throw statementMalformed(statement);
  return {
    kind,
    subject,
    value,
    place: place === undefined ? "/" : checkedKey(place, canonical),
    expiresAt: expiresAt === undefined ? undefined : assertTime(expiresAt),
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- every member the type names was checked above
    source: statement as unknown as Statement,
  };
}

function checkedKey(place: unknown, canonical: Set<string>): string {
  if (typeof place === "string" && canonical.has(place)) return place;
  const key = assertKey(place);
  canonical.add(key);
  return key;
}
