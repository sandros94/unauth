import { compiledOf } from "./_internal/compile.ts";
import type { CompiledCatalog } from "./_internal/compiled.ts";
import { malformed } from "./_internal/errors.ts";
import { coversPlace, readSet } from "./_internal/grants-read.ts";
import { issueSet } from "./_internal/grants-issue.ts";
import { readGrantsSet } from "./_internal/grants-validate.ts";
import { assertKey } from "./_internal/keys.ts";
import { readAsked, readAsker } from "./_internal/question.ts";
import { roleReader } from "./_internal/roles.ts";
import { readStatements } from "./_internal/statements.ts";
import { assertFits } from "./_internal/structure.ts";
import { clockSeconds } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type { StatementsOptions } from "./decide.ts";
import type { Decision, Grants, GrantsQuestion } from "./types.ts";

/** Options of {@link issueGrants}. */
export interface IssueGrantsOptions extends StatementsOptions {
  /** Every group the subject belongs to. */
  groups?: readonly string[];
  /** The places the grants speak for: a question elsewhere is answered as not covered. @default ["/"] */
  bases?: readonly string[];
}

/**
 * Writes what the statements about a subject amount to, to be carried in a session or a token and
 * read with {@link readGrants} without the statements. Each value keeps its own end, so nothing
 * is issued again when a statement expires, only when one is written or removed.
 *
 * Needs every statement about the subject and each of its groups. With `bases`, those at the
 * places covering a base and under it are enough (`placeChain`, `placeRange`).
 *
 * @throws `ERR_AUTHZ_PLACE_OUTSIDE` or `ERR_AUTHZ_MALFORMED` for a base that is not a place of the catalog.
 */
export function issueGrants(
  catalog: Catalog,
  subject: string,
  options: IssueGrantsOptions,
): Grants {
  const compiled = compiledOf(catalog);
  const asker = readAsker({ subject, groups: options?.groups });
  const bases = readBases(compiled, options?.bases);
  const time = clockSeconds(options);
  const roles = roleReader(compiled, options?.roles);
  const statements = readStatements(compiled, options?.statements);
  return issueSet(compiled, roles, statements, { ...asker, bases, time });
}

/**
 * Answers a question from grants alone: no statements, no storage. `grants` is one set, or a list
 * of sets read together: an array is a list, anything else is one set. It takes whatever a carrier
 * handed over, a cookie payload or a parsed row, and checks every set whole before reading. Sets
 * read together cover a place when any of them covers it, and allow only when every set that
 * covers it allows.
 *
 * `by` is what decided in the first covering set that does not allow, else in the first covering
 * set. A stored role is named by its row, `#` and its index, since grants keep what it gave and
 * not its name.
 *
 * @throws `ERR_AUTHZ_MALFORMED` for grants that are not what {@link issueGrants} writes.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` or `ERR_AUTHZ_GRANTS_CATALOG` for grants of another format
 * revision or issued for another catalog: issue them again.
 * @throws `ERR_AUTHZ_GRANTS_EARLY` when the clock reads earlier than their issue.
 * @throws what {@link decide} throws for the question.
 *
 * @example
 * const { allowed, covered } = readGrants(catalog, session.data.grants, { permission: "report:read", place });
 */
export function readGrants<TPermission extends string>(
  catalog: Catalog<TPermission>,
  grants: unknown,
  question: GrantsQuestion<NoInfer<TPermission>>,
  options?: Pick<StatementsOptions, "now">,
): Decision {
  const compiled = compiledOf(catalog);
  const time = clockSeconds(options);
  const list: readonly unknown[] = Array.isArray(grants) ? grants : [grants];
  const sets = list.map((set) => readGrantsSet(compiled, set, time));
  const asked = readAsked(compiled, question);
  let decisive: Omit<Decision, "covered"> | undefined;
  for (const set of sets) {
    if (!coversPlace(set, asked.place)) continue;
    const answer = readSet(compiled, set, { ...asked, time });
    if (!decisive || !answer.allowed) decisive = answer;
    if (!answer.allowed) break;
  }
  return decisive ? { ...decisive, covered: true } : { allowed: false, covered: false };
}

/**
 * Whether grants allow the permission: {@link readGrants} as one boolean, for the check most
 * routes make, taking `grants` as it does. A place the grants do not cover is `false`.
 *
 * @example
 * if (!can(catalog, session.data.grants, "report:read", { place })) throw forbidden();
 */
export function can<TPermission extends string>(
  catalog: Catalog<TPermission>,
  grants: unknown,
  permission: NoInfer<TPermission>,
  options?: CanOptions,
): boolean {
  const question = { permission, place: options?.place };
  return readGrants(catalog, grants, question, { now: options?.now }).allowed;
}

/** Options of {@link can}. */
export interface CanOptions extends Pick<StatementsOptions, "now"> {
  /** The key of the place asked about. Absent is the root. */
  place?: string;
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
  options?: Pick<StatementsOptions, "now">,
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
