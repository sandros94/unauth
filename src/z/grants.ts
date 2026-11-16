import { compiledOf } from "./_internal/compile.ts";
import type { CompiledCatalog } from "./_internal/compiled.ts";
import { malformed, optionInvalid } from "./_internal/errors.ts";
import { divergedOf } from "./_internal/grants/diverged.ts";
import { type GrantsHead, assertIssued, basesOf, readHead } from "./_internal/grants/form.ts";
import { issueSet } from "./_internal/grants/issue.ts";
import { readSet } from "./_internal/grants/read.ts";
import { heldRoles } from "./_internal/grants/roles.ts";
import { assertGrantsSet } from "./_internal/grants/validate.ts";
import { assertKey, covers } from "./_internal/keys.ts";
import { readAsked, readAskedPlace } from "./_internal/question.ts";
import { indexRoles } from "./_internal/roles.ts";
import { readSubjectStatements, readWrittenStatements } from "./_internal/statements.ts";
import { assertFits } from "./_internal/structure.ts";
import { clockSeconds, readTimes } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type {
  Decision,
  Diverged,
  Grants,
  GrantsPart,
  Question,
  Statement,
  SubjectStatements,
} from "./types.ts";

/** Options of {@link issueGrants}. */
export interface IssueGrantsOptions {
  /** The places the grants speak for: a question elsewhere is answered as not covered. @default ["/"] */
  bases?: readonly string[];
  /**
   * The parts that travel by name instead of as copies. With `["presets"]`, the grants hold no
   * copy of the presets they name: they are smaller, and a preset they name means what the catalog
   * in force declares when they are read, so a changed preset reaches them without a reissue.
   * @default []
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
 * entry not in its one form.
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for `omit` that is not a list of parts of grants.
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

/** Options of {@link could}. */
export interface CouldOptions {
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
  /**
   * How far the clock of the read may be off from the clock that issued the grants, in whole
   * seconds. Under it, grants are refused as issued in the future only when the time plus it
   * is earlier than their issue, and an item is live while its end plus it is later than the time,
   * for a deny and an exclusion as for an allow. A read and `ask` at the same time may then differ
   * on what ended less than it before. Keep it small. @default 0
   */
  clockTolerance?: number;
}

/**
 * Answers a question from grants alone, as `ask` answers it from the statements they were issued
 * from: no statements, no storage. `grants` is one set, or a list of sets read together: an array
 * is a list, anything else is one set. It takes whatever a carrier handed over, a cookie payload or
 * a parsed row, and reads of each set only what the question looks up: `v`, `ct`, `at` and `bs`,
 * then, of a set whose bases cover the place, the entries of the values that can bear on the
 * permission, the places their items point at and the definitions of the roles it resolves. A
 * place is checked to be text and then only compared byte by byte with the keys covering the place
 * asked: one in another spelling of a key gives nothing there. What it does not read is not
 * checked: {@link assertGrants} checks a set whole. Sets read together cover a place when any of
 * them covers it, and allow only when every set that covers it allows.
 *
 * Grants issued under another catalog are read with what it declares now: a pattern matches the
 * permissions declared now, an implication holds as declared now, a preset the grants name without
 * a copy is the catalog's, and what it no longer knows is inert. A role name is found in the
 * copies of `ps`, then in the stored roles of `sr`, then among the presets of the catalog. `diverged`
 * tells what of the sets differs from this catalog, on every answer.
 *
 * `by` is what decided in the first covering set that does not allow, else in the first covering
 * set. A role, preset or stored, is named by its name, a permission by its name, also where the
 * grants carry its position in `pm`. When several values give alike, a direct allow is named before
 * a role, and roles in the order they are looked up: `ps`, `sr`, then the catalog's presets.
 *
 * The question is checked first, so a question that cannot be asked is refused whatever the
 * grants hold.
 *
 * `clockTolerance` is for a clock that is not the one that issued the grants, another server's or
 * a browser's. Under it an end counts that much later, for a deny and an exclusion as for an
 * allow, and the read is refused only when the time is earlier than the issue by more than it. A
 * read and `ask` at the same time then differ on what ended less than the tolerance before it.
 * Absent, none applies.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for grants not in the form {@link issueGrants} writes, in what the
 * question reads of them, and, when a segment of the fingerprint differs, in `pm`, `ps` and `sr`,
 * read whole to tell what has diverged, with the names of `nt` in a set without `pm`.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` for grants of another format revision.
 * @throws `ERR_AUTHZ_GRANTS_FUTURE` when the clock reads earlier than their issue by more than
 * `clockTolerance`.
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for a `clockTolerance` that is not a non-negative whole
 * number of seconds.
 * @throws what `ask` throws for the question.
 *
 * @example
 * const { allowed, covered, diverged } = could(catalog, session.data.grants, { permission: "report:read", place });
 */
export function could<TPermission extends string>(
  catalog: Catalog<TPermission>,
  grants: unknown,
  question: Question<NoInfer<TPermission>>,
  options?: CouldOptions,
): Decision<Omit<Statement, "subject">> {
  const compiled = compiledOf(catalog);
  const { latest, earliest } = readTimes(options);
  const asked = readAsked(compiled, question);
  const sets = readHeads(grants, latest);
  const covering = coveringOf(sets, asked.place);
  let decisive: Omit<Decision<Omit<Statement, "subject">>, "covered"> | undefined;
  for (const set of covering) {
    const answer = readSet(compiled, set, { ...asked, time: earliest });
    if (!decisive || (decisive.allowed && !answer.allowed)) decisive = answer;
  }
  const decision = decisive ? { ...decisive, covered: true } : { allowed: false, covered: false };
  const told = divergedOf(compiled, sets);
  return told ? { ...decision, diverged: told } : decision;
}

/** Options of {@link diverged}. */
export interface DivergedOptions {
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
  /** The clock tolerance in whole seconds, as {@link CouldOptions} defines it. @default 0 */
  clockTolerance?: number;
}

/**
 * What of grants differs from the catalog in force, without a question: `could` tells the same on
 * every answer. `undefined` when every set was issued under this very catalog, and then nothing but
 * `v`, `ct` and `at` is read. `presets` names every role the grants hold whose name no longer means
 * the same: a copy whose preset changed or left, and a stored role whose name the catalog now
 * declares as a preset with other entries. `grants` is taken as {@link could} takes it, one set or
 * a list. When a segment differs, `pm`, `ps` and `sr` are read whole, and checked.
 *
 * @throws `ERR_AUTHZ_MALFORMED`, `ERR_AUTHZ_GRANTS_FORMAT` and `ERR_AUTHZ_GRANTS_FUTURE` as
 * {@link could} throws them, for what it reads, and `ERR_UNAUTH_CONFIG_INVALID` for
 * `clockTolerance` as {@link could} does.
 *
 * @example
 * const told = diverged(catalog, session.data.grants);
 * if (told?.presets.length) await reissue(session);
 */
export function diverged(
  catalog: Catalog,
  grants: unknown,
  options?: DivergedOptions,
): Diverged | undefined {
  const compiled = compiledOf(catalog);
  return divergedOf(compiled, readHeads(grants, readTimes(options).latest));
}

/** Options of {@link assertGrants}. */
export interface AssertGrantsOptions {
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
  /** The clock tolerance in whole seconds, as {@link CouldOptions} defines it. @default 0 */
  clockTolerance?: number;
}

/**
 * Checks one set of grants whole against its form, and types it: every member the model defines,
 * every entry, every item, every place and every definition, where {@link could} checks only what
 * a question reads. For where the application receives grants it did not issue itself: once, there,
 * instead of in every route. An array is not one set. Whether the catalog knows what the grants
 * name is not checked: what it does not know is inert when read.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for a value that is not in the form {@link issueGrants} writes, an
 * array included.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` for grants of another format revision.
 * @throws `ERR_AUTHZ_GRANTS_FUTURE` when the clock reads earlier than their issue by more than
 * `clockTolerance`.
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for `clockTolerance` as {@link could} does.
 *
 * @example
 * const grants = payload.grants;
 * assertGrants(catalog, grants);
 * session.grants = grants;
 */
export function assertGrants(
  catalog: Catalog,
  value: unknown,
  options?: AssertGrantsOptions,
): asserts value is Grants {
  compiledOf(catalog);
  const { latest } = readTimes(options);
  if (Array.isArray(value)) {
    throw malformed("The grants are not one set.", { what: "grants", value });
  }
  assertGrantsSet(value, latest);
}

/** Options of {@link rolesOf}. */
export interface RolesOfOptions {
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
  /** The clock tolerance in whole seconds, as {@link CouldOptions} defines it. @default 0 */
  clockTolerance?: number;
}

/**
 * The names of the roles held at the place asked, for an interface that shows or hides things by
 * role. Never a gate on a server: a role held says nothing of a deny or an exclusion, and whether
 * something is allowed is asked with {@link could}.
 *
 * A role is held when one of its assignment items is live at the time of the call, under
 * `clockTolerance` as `could` reads it, at the place asked or at a place covering it. The names
 * are sorted by bytes, each once. `question` is the question as `could` takes it, of which only
 * `place` is read: absent, or with no `place`, it asks at the root. `grants` is one set or a list,
 * as `could` takes it, and a set whose bases do not cover the place gives nothing.
 *
 * It lists assigned names only: someone assigned `editor`, whose definition names `viewer`, holds
 * `editor` and not `viewer`. A role is found as `could` finds it: the names `ps` and `sr` hold and
 * the presets of the catalog in force, each looked up in `nt`. No role is resolved and no
 * definition is read: of each set it reads `v`, `ct`, `at` and `bs`, then, of a set that covers
 * the place, the entries under those names with their items, and the places those items point at.
 * A read costs one pass over the role names, so an interface computes the list once and checks it
 * many times.
 *
 * The question is checked first, so a question that cannot be asked is refused whatever the
 * grants hold.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`question`) for a question that is not an object.
 * @throws `ERR_AUTHZ_MALFORMED` (`place`) for a place that is not canonical, and
 * `ERR_AUTHZ_PLACE_OUTSIDE` for one that does not fit the catalog.
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for what it reads that is not in the form
 * {@link issueGrants} writes, an entry found under a role name, one of its items and a place an
 * item points at that is not a string included.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` and `ERR_AUTHZ_GRANTS_FUTURE` as {@link could} throws them.
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for `clockTolerance` as {@link could} does.
 *
 * @example
 * const roles = rolesOf(catalog, session.data.grants, { place });
 * const showSettings = roles.includes("admin");
 *
 * @example
 * const roles = rolesOf(catalog, session.data.grants, { place });
 * const showReview = roles.some((role) => role === "editor" || role === "reviewer");
 */
export function rolesOf(
  catalog: Catalog,
  grants: unknown,
  question?: Pick<Question, "place">,
  options?: RolesOfOptions,
): string[] {
  const compiled = compiledOf(catalog);
  const { latest, earliest } = readTimes(options);
  const place = readAskedPlace(compiled, question);
  const sets = readHeads(grants, latest);
  return heldRoles(compiled, coveringOf(sets, place), { place, time: earliest });
}

function readHeads(grants: unknown, time: number): GrantsHead[] {
  const list: readonly unknown[] = Array.isArray(grants) ? grants : [grants];
  return list.map((set) => {
    const head = readHead(set);
    assertIssued(head, time);
    return head;
  });
}

function coveringOf(sets: readonly GrantsHead[], place: string): GrantsHead[] {
  return sets.filter(({ grants }) => basesOf(grants).some((base) => covers(base, place)));
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
    throw optionInvalid("omit", "a list of parts of grants", omit);
  }
  return new Set(omit);
}

function isPart(value: unknown): value is GrantsPart {
  return value === "presets";
}
