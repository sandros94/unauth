import { compiledOf } from "./_internal/compile.ts";
import { decidePermission } from "./_internal/decide.ts";
import { readAsked, readAsker } from "./_internal/question.ts";
import { roleReader } from "./_internal/roles.ts";
import { readStatements } from "./_internal/statements.ts";
import { clockSeconds } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type { Decision, Question, Statement, StoredRole } from "./types.ts";

/**
 * The engine: pure functions that compute and read nothing. Statements are the application's own
 * rows, read by its own query, in its own transaction, and handed in. Each function says which
 * statements it needs. Handing in more is always safe, since what does not bear on the call is
 * ignored. Handing in fewer is not: a deny that was not read is a deny that does not block.
 */

/** What every function that computes from statements takes. */
export interface StatementsOptions {
  /** The statements read for this call. */
  statements: readonly Statement[];
  /** The stored roles those statements assign, with the roles they reference. Omit without stored roles. */
  roles?: readonly StoredRole[];
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
}

/**
 * Answers a question from statements: the fresh answer, whatever grants were issued before.
 *
 * Needs the statements about the subject and each of its groups at the places covering the one
 * asked (`placeChain`). Every statement about them is the simple query that cannot miss one.
 *
 * @throws `ERR_AUTHZ_QUESTION_INVALID` for no permission or a wildcard.
 * @throws `ERR_AUTHZ_PERMISSION_UNKNOWN` for a permission the catalog does not declare.
 * @throws `ERR_AUTHZ_PLACE_OUTSIDE` for a place the catalog's structure does not hold.
 * @throws `ERR_AUTHZ_MALFORMED` for a place that is not a canonical key.
 *
 * @example
 * const statements = await db.select().from(grantsTable).where(
 *   and(inArray(grantsTable.subject, [userId, ...teams]), inArray(grantsTable.place, placeChain(place))),
 * );
 * const { allowed } = decide(catalog, { subject: userId, groups: teams, permission: "report:read", place }, { statements });
 */
export function decide<TPermission extends string>(
  catalog: Catalog<TPermission>,
  question: Question<NoInfer<TPermission>>,
  options: StatementsOptions,
): Decision {
  const compiled = compiledOf(catalog);
  const asked = readAsked(compiled, question);
  const { subject, groups } = readAsker(question);
  const time = clockSeconds(options);
  const source = {
    catalog: compiled,
    roles: roleReader(compiled, options?.roles),
    statements: readStatements(compiled, options?.statements),
  };
  const { allowed, by } = decidePermission(source, { ...asked, subject, groups, time });
  return by ? { allowed, covered: true, by: by.source } : { allowed, covered: true };
}
