import { compiledOf } from "./_internal/compile.ts";
import type { CompiledCatalog } from "./_internal/compiled.ts";
import { malformed } from "./_internal/errors.ts";
import { coversPlace, readSet } from "./_internal/grants/read.ts";
import { issueSet } from "./_internal/grants/issue.ts";
import { divergedOf } from "./_internal/grants/diverged.ts";
import { type GrantsSetRead, readGrantsSet } from "./_internal/grants/validate.ts";
import { assertKey } from "./_internal/keys.ts";
import { readAsked } from "./_internal/question.ts";
import { indexRoles } from "./_internal/roles.ts";
import { readSubjectStatements, readWrittenStatements } from "./_internal/statements.ts";
import { assertFits } from "./_internal/structure.ts";
import { clockSeconds } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type {
  Decision,
  Diverged,
  Grants,
  GrantsPart,
  Question,
  QuestionOptions,
  Statement,
  SubjectStatements,
} from "./types.ts";

/** Options of {@link issueGrants}. */
export interface IssueGrantsOptions {
  /** The places the grants speak for: a question elsewhere is answered as not covered. @default ["/"] */
  bases?: readonly string[];
  /**
   * The parts that travel by name instead of as copies. With `["presets"]`, the grants hold no
   * copy of the presets they name: they are smaller, and a read refuses grants that name a preset
   * once the catalog's presets are no longer those of issue. @default []
   */
  omit?: readonly GrantsPart[];
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
 * Statements are kept as written, so a later catalog reads them with what it declares: one the
 * catalog does not know yet is kept too, and so is an assignment of a role that gives nothing.
 * Only an assignment of a role that cannot be resolved is left out: a role that is neither a
 * preset nor a stored role handed in, one that references such a role, with or without `-`, and
 * one on a cycle of references. Roles travel as defined, never resolved: a stored role with its
 * definition, a preset with a copy of its definition unless `omit` names `presets`.
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
 * @throws `ERR_AUTHZ_MALFORMED` (`entry`) for a stored role whose definition is written with an
 * entry not in its one form, (`omit`) for `omit` that is not a list of parts of grants.
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
  const copies = !readOmit(options?.omit).has("presets");
  const time = clockSeconds(options);
  const stored = indexRoles(roles);
  const written = readWrittenStatements(statements);
  return issueSet(compiled, stored, written, { subject, bases, time, copies });
}

/**
 * Answers a question from grants alone, as `ask` answers it from the statements they were issued
 * from: no statements, no storage. `grants` is one set, or a list of sets read together: an array
 * is a list, anything else is one set. It takes whatever a carrier handed over, a cookie payload or
 * a parsed row, and checks every set whole before reading. Sets read together cover a place when
 * any of them covers it, and allow only when every set that covers it allows.
 *
 * Grants issued under another catalog are read with what it declares now: a pattern matches the
 * permissions declared now, an implication holds as declared now, and what it no longer knows is
 * inert. A role is resolved from the definitions the grants hold, a preset they hold a copy of as
 * it was at issue. `diverged` tells what of the sets differs from this catalog, on every answer.
 *
 * `by` is what decided in the first covering set that does not allow, else in the first covering
 * set. A role, preset or stored, is named by its name, a permission by its name, also where the
 * grants carry its position in `pm`.
 *
 * The question is checked first, so a question that cannot be asked is refused whatever the
 * grants hold.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for grants that are not in the form {@link issueGrants} writes.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` for grants of another format revision.
 * @throws `ERR_AUTHZ_GRANTS_CATALOG` (`presets`) for grants that carry a preset by name, read under
 * other presets than those of their issue: issue them again.
 * @throws `ERR_AUTHZ_GRANTS_EARLY` when the clock reads earlier than their issue.
 * @throws what `ask` throws for the question.
 *
 * @example
 * const { allowed, covered, diverged } = could(catalog, session.data.grants, { permission: "report:read", place });
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
  const sets = readSets(compiled, grants, time);
  let decisive: Omit<Decision<Omit<Statement, "subject">>, "covered"> | undefined;
  for (const set of sets) {
    if (!coversPlace(set, asked.place)) continue;
    const answer = readSet(compiled, set, { ...asked, time });
    if (!decisive || !answer.allowed) decisive = answer;
    if (!answer.allowed) break;
  }
  const decision = decisive ? { ...decisive, covered: true } : { allowed: false, covered: false };
  const told = divergedOf(compiled, sets);
  return told ? { ...decision, diverged: told } : decision;
}

/**
 * What of grants differs from the catalog in force, without a question: `could` tells the same on
 * every answer. `undefined` when every set was issued under this very catalog. `presets` names
 * every role the grants hold whose name no longer means the same: a copy whose preset changed or
 * left, and a stored role whose name the catalog now declares as a preset with other entries. `grants` is taken
 * as {@link could} takes it, one set or a list, and checked as a read checks it.
 *
 * @throws what {@link could} throws for the grants.
 *
 * @example
 * const told = diverged(catalog, session.data.grants);
 * if (told?.presets.length) await reissue(session);
 */
export function diverged(
  catalog: Catalog,
  grants: unknown,
  options?: QuestionOptions,
): Diverged | undefined {
  const compiled = compiledOf(catalog);
  return divergedOf(compiled, readSets(compiled, grants, clockSeconds(options)));
}

/**
 * Checks one set of grants exactly as a read checks it, and types it. For typing a value once,
 * where it enters the application, and handling a refused set there (presets changed: issue the
 * grants again) instead of in every route. An array is not one set.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a value that is not in the form {@link issueGrants} writes, an
 * array included.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` or `ERR_AUTHZ_GRANTS_CATALOG` as {@link could} throws them.
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

function readSets(catalog: CompiledCatalog, grants: unknown, time: number): GrantsSetRead[] {
  const list: readonly unknown[] = Array.isArray(grants) ? grants : [grants];
  return list.map((set) => readGrantsSet(catalog, set, time));
}

function readBases(catalog: CompiledCatalog, bases: unknown): string[] {
  if (bases === undefined) return ["/"];
  if (!Array.isArray(bases) || bases.length === 0) {
    throw malformed("The bases are not a list of places.", { what: "place", value: bases });
  }
  return bases.map((base: unknown) => assertFits(catalog, assertKey(base)));
}

function readOmit(omit: unknown): Set<GrantsPart> {
  if (omit === undefined) return new Set();
  if (!Array.isArray(omit) || !omit.every(isPart)) {
    throw malformed("The parts to omit are not parts of grants.", { what: "omit", value: omit });
  }
  return new Set(omit);
}

function isPart(value: unknown): value is GrantsPart {
  return value === "presets";
}
