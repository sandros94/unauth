import { isUnauthError } from "../error.ts";
import { compiledOf } from "./_internal/compile.ts";
import type { CompiledCatalog } from "./_internal/compiled.ts";
import { malformed } from "./_internal/errors.ts";
import { coversPlace, readSet } from "./_internal/grants/read.ts";
import { issueSet } from "./_internal/grants/issue.ts";
import { readGrantsSet } from "./_internal/grants/validate.ts";
import { assertKey } from "./_internal/keys.ts";
import { readAsked } from "./_internal/question.ts";
import { roleReader } from "./_internal/roles.ts";
import { readStatements, readSubjectStatements } from "./_internal/statements.ts";
import { assertFits } from "./_internal/structure.ts";
import { clockSeconds } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type {
  Decision,
  Grants,
  Question,
  QuestionOptions,
  Statement,
  SubjectStatements,
} from "./types.ts";

/** Options of {@link issueGrants}. */
export interface IssueGrantsOptions {
  /** The places the grants speak for: a question elsewhere is answered as not covered. @default ["/"] */
  bases?: readonly string[];
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
}

/**
 * Writes what the statements that apply to a subject amount to, to be carried in a session or a
 * token and read with {@link could} without the statements. Each value keeps its own end, so
 * nothing is issued again when a statement expires, only when one is written or removed. Every
 * statement handed in applies, as it does for `ask`: what a group gave, the group being any
 * subject but `read.subject`, is bundled with that group's exclusions.
 *
 * Needs every live statement about the subject and each of its groups, and the stored roles they
 * assign. With `bases`, those at the places covering a base and under it are enough (`placeChain`,
 * `placeRange`).
 *
 * @throws `ERR_AUTHZ_PLACE_OUTSIDE` or `ERR_AUTHZ_MALFORMED` (`place`) for a base that is not a
 * place of the catalog.
 * @throws `ERR_AUTHZ_MALFORMED` for a subject that is not a non-empty string (`subject`),
 * statements not in their shape (`statement`), stored roles not in theirs (`roles`).
 * @throws `ERR_AUTHZ_ROLE_INVALID` (`duplicate`) for two stored roles of one name.
 *
 * @example
 * const grants = issueGrants(catalog, { subject: userId, statements, roles }, { bases: [place] });
 */
export function issueGrants(
  catalog: Catalog,
  read: SubjectStatements,
  options?: IssueGrantsOptions,
): Grants {
  const compiled = compiledOf(catalog);
  const { subject, statements, roles } = readSubjectStatements(read);
  const bases = readBases(compiled, options?.bases);
  const time = clockSeconds(options);
  const reader = roleReader(compiled, roles);
  const readList = readStatements(compiled, statements);
  return issueSet(compiled, reader, readList, { subject, bases, time });
}

/**
 * Answers a question from grants alone, as `ask` answers it from the statements they were issued
 * from: no statements, no storage. `grants` is one set, or a list
 * of sets read together: an array is a list, anything else is one set. It takes whatever a carrier
 * handed over, a cookie payload or a parsed row, and checks every set whole before reading. Sets
 * read together cover a place when any of them covers it, and allow only when every set that
 * covers it allows.
 *
 * `by` is what decided in the first covering set that does not allow, else in the first covering
 * set. A stored role is named by its row, `#` and its index, since grants keep what it gave and
 * not its name.
 *
 * The question is checked first, so a question that cannot be asked is refused whatever the
 * grants hold.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for grants that are not what {@link issueGrants} writes.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` or `ERR_AUTHZ_GRANTS_CATALOG` for grants of another format
 * revision or issued for another catalog: issue them again.
 * @throws `ERR_AUTHZ_GRANTS_EARLY` when the clock reads earlier than their issue.
 * @throws what `ask` throws for the question.
 *
 * @example
 * const { allowed, covered } = could(catalog, session.data.grants, { permission: "report:read", place });
 */
export function could<TPermission extends string>(
  catalog: Catalog<TPermission>,
  grants: unknown,
  question: Question<NoInfer<TPermission>>,
  options?: QuestionOptions,
): Decision<Omit<Statement, "subject">> {
  const compiled = compiledOf(catalog);
  const time = clockSeconds(options);
  const asked = readAsked(compiled, question);
  const list: readonly unknown[] = Array.isArray(grants) ? grants : [grants];
  const sets = list.map((set) => readGrantsSet(compiled, set, time));
  let decisive: Omit<Decision<Omit<Statement, "subject">>, "covered"> | undefined;
  for (const set of sets) {
    if (!coversPlace(set, asked.place)) continue;
    const answer = readSet(compiled, set, { ...asked, time });
    if (!decisive || !answer.allowed) decisive = answer;
    if (!answer.allowed) break;
  }
  return decisive ? { ...decisive, covered: true } : { allowed: false, covered: false };
}

/**
 * Whether grants allow the permission: {@link could} as one boolean, taking `grants` as it does,
 * for what only shows or hides. A place the grants do not cover is `false`, and so are grants a
 * read refuses: malformed, of another format revision, issued for another catalog or read before
 * their issue. Where those must be told apart, to issue the grants again or to answer each case,
 * use {@link could}. The question is checked first, as `could` checks it.
 *
 * @throws what `ask` throws for the question, whatever the grants hold.
 *
 * @example
 * const canPublish = can(catalog, session.data.grants, { permission: "post:publish", place });
 */
export function can<TPermission extends string>(
  catalog: Catalog<TPermission>,
  grants: unknown,
  question: Question<NoInfer<TPermission>>,
  options?: QuestionOptions,
): boolean {
  try {
    return could(catalog, grants, question, options).allowed;
  } catch (error) {
    if (isRefusedGrants(error)) return false;
    throw error;
  }
}

/**
 * Checks one set of grants exactly as a read checks it, and types it. For typing a value once,
 * where it enters the application, and handling a refused set there (another catalog: issue the
 * grants again) instead of in every route. An array is not one set.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a value that is not what {@link issueGrants} writes, an array
 * included.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` or `ERR_AUTHZ_GRANTS_CATALOG` for grants of another format
 * revision or issued for another catalog.
 * @throws `ERR_AUTHZ_GRANTS_EARLY` when the clock reads earlier than their issue.
 *
 * @example
 * const grants = payload.grants;
 * assertGrants(catalog, grants);
 * session.grants = grants;
 */
export function assertGrants(
  catalog: Catalog,
  value: unknown,
  options?: QuestionOptions,
): asserts value is Grants {
  const compiled = compiledOf(catalog);
  if (Array.isArray(value)) {
    throw malformed("The grants are not one set.", { what: "grants", value });
  }
  readGrantsSet(compiled, value, clockSeconds(options));
}

function readBases(catalog: CompiledCatalog, bases: unknown): string[] {
  if (bases === undefined) return ["/"];
  if (!Array.isArray(bases) || bases.length === 0) {
    throw malformed("The bases are not a list of places.", { what: "place", value: bases });
  }
  return bases.map((base: unknown) => assertFits(catalog, assertKey(base)));
}

function isRefusedGrants(error: unknown): boolean {
  if (isUnauthError(error, "ERR_AUTHZ_MALFORMED")) return error.cause.what === "grants";
  return (
    isUnauthError(error, "ERR_AUTHZ_GRANTS_FORMAT") ||
    isUnauthError(error, "ERR_AUTHZ_GRANTS_CATALOG") ||
    isUnauthError(error, "ERR_AUTHZ_GRANTS_EARLY")
  );
}
