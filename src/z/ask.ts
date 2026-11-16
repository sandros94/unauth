import { compiledOf } from "./_internal/compile.ts";
import { decidePermission } from "./_internal/decide.ts";
import { readAsked } from "./_internal/question.ts";
import { askedRoleReader } from "./_internal/roles.ts";
import { readAskedStatements, readSubjectStatements } from "./_internal/statements.ts";
import { clockSeconds } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type { Decision, Question, Statement, SubjectStatements } from "./types.ts";

/** Options of {@link ask}. */
export interface AskOptions {
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
}

/**
 * Answers a question from the statements that apply to a subject: the fresh answer, whatever
 * grants were issued before. The engine reads nothing: the application reads the statements, by
 * its own query in its own transaction, and hands them in. Every statement handed in applies, the
 * subject's own and its groups', so handing in a statement about a subject it does not belong to
 * counts as a group's, and leaving a group's out is a deny that does not block.
 *
 * Needs the live statements about the subject and each of its groups at the places covering the
 * one asked (`placeChain`), and the stored roles they assign. Only those carrying the values
 * `relatedValues` names can change the answer. `by` is the statement handed in that decided.
 *
 * Reads only what the question looks up: the statements whose place is byte-equal to a key of the
 * chain, an absent place being the root, and of those the assignments and the statements whose
 * value is one `relatedValues` names for their kind; of the stored roles, the name of each, and
 * the role itself once an assignment read names it. To find them it reads the place of every item
 * handed in, wherever it sits and whatever the question: an item that is not an object, and an
 * object whose place is present and is not a string, `null` included, are refused, since they give
 * nothing to compare. Nothing else handed in is checked: a statement under another spelling of a
 * key is at no place asked about, and counts for nothing. `validateStatement` is what catches it,
 * before the write.
 *
 * @throws `ERR_AUTHZ_QUESTION_INVALID` for no permission or a wildcard.
 * @throws `ERR_AUTHZ_PERMISSION_UNKNOWN` for a permission the catalog does not declare.
 * @throws `ERR_AUTHZ_PLACE_OUTSIDE` for a place the catalog's structure does not hold.
 * @throws `ERR_AUTHZ_MALFORMED` for a place asked that is not a canonical key, or the place of an
 * item handed in present and not a string (`place`), a subject that is not a non-empty string
 * (`subject`), statements that are not a list, an item of it that is not an object or a statement
 * read not in its shape (`statement`, `time`), stored roles that are not a list or a stored role
 * read not in its shape (`roles`), and a clock that does not read a time (`time`).
 * @throws `ERR_AUTHZ_ROLE_INVALID` (`duplicate`) for two stored roles of a name the question reads.
 *
 * @example
 * const statements = await db.select().from(statementsTable).where(
 *   and(inArray(statementsTable.subject, [userId, ...teams]), inArray(statementsTable.place, placeChain(place))),
 * );
 * const { allowed } = ask(catalog, { subject: userId, statements }, { permission: "report:read", place });
 */
export function ask<TPermission extends string, TStatement extends Statement>(
  catalog: Catalog<TPermission>,
  read: SubjectStatements<TStatement>,
  question: Question<NoInfer<TPermission>>,
  options?: AskOptions,
): Decision<TStatement> {
  const compiled = compiledOf(catalog);
  const asked = readAsked(compiled, question);
  const { subject, statements, roles } = readSubjectStatements(read);
  const time = clockSeconds(options);
  const source = {
    catalog: compiled,
    roles: askedRoleReader(compiled, roles),
    statements: readAskedStatements(compiled, statements, asked),
  };
  const { allowed, by } = decidePermission(source, { ...asked, subject, time });
  if (!by) return { allowed, covered: true };
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the source is the very object handed in
  return { allowed, covered: true, by: by.source as TStatement };
}
