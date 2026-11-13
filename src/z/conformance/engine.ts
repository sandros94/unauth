import type { Catalog, CatalogData } from "../catalog.ts";
import type { Statement, StoredRole } from "../types.ts";

/** "May the subject do this, here?": one permission at one place, asked of statements or grants. */
export interface Question {
  /** The permission asked. Never a wildcard. */
  permission: string;
  /** The key of the place asked about. Absent is the root. */
  place?: string;
}

/**
 * What an application hands an engine for one subject: the subject's own identifier and the
 * statements that apply to it. A statement about another identifier counts as one of its groups'.
 */
export interface SubjectStatements {
  subject: string;
  statements: readonly Statement[];
  /** The stored roles the statements assign, with the roles those reference. */
  roles?: readonly StoredRole[];
}

/**
 * What of grants differs from the catalog they are read under: the segments of the fingerprint
 * that differ, the preset copies that have diverged, and the permissions the grants name that the
 * catalog does not declare. Every member is always present, each list sorted by bytes.
 */
export interface Diverged {
  segments: ("permissions" | "presets")[];
  permissions: string[];
  presets: string[];
}

/** The answer to a question, as the cases read it. */
export interface Decision {
  allowed: boolean;
  /** `false` only when grants do not speak for the place asked. */
  covered: boolean;
  /** For a question asked of grants: what has diverged, present whenever something has. */
  diverged?: Diverged;
}

/** One problem validation found in a value, at the member `path` names. */
export interface Issue {
  code: string;
  /** `["kind"]`, `["entries", 2]`, or `[]` when the value is not an object. */
  path: readonly (string | number)[];
  message: string;
  cause?: unknown;
}

/** The time a call is made at. */
export interface ClockOptions {
  /** The clock, in ms, read once. @default Date.now */
  now?: () => number;
}

/** A part of grants an application may leave out at issue: `"presets"` carries presets by name alone. */
export type GrantsPart = "presets";

/** What issuing grants is handed beside the statements. */
export interface IssueGrantsOptions extends ClockOptions {
  /** The places the grants speak for. @default the root */
  bases?: readonly string[];
  /** What to leave out. @default nothing: presets travel as copies */
  omit?: readonly GrantsPart[];
}

/** What validating a stored role is handed beside it. */
export interface ValidateOptions {
  /** The stored roles the application keeps, those it names and those naming it included. */
  roles?: readonly StoredRole[];
}

/** What validating a statement is handed beside it. */
export interface ValidateStatementOptions extends ValidateOptions, ClockOptions {}

/**
 * The functions of an engine the cases call: those of `unauth/z`, or others of the same shape.
 * Each one either answers or throws an `UnauthError` whose `code` names the refusal.
 */
export interface Engine {
  defineCatalog(data: CatalogData): Catalog;
  /** Answers a question from the statements handed over, every one taken as applying. */
  ask(
    catalog: Catalog,
    read: SubjectStatements,
    question: Question,
    options?: ClockOptions,
  ): Decision;
  /** Answers a question from grants, one set or several read together. */
  could(catalog: Catalog, grants: unknown, question: Question, options?: ClockOptions): Decision;
  /**
   * What of grants, one set or several, has diverged from the catalog, without a question:
   * `undefined` when both segments of every set match. Refuses what every read refuses, and, of a
   * set whose segment differs, a permission table, a preset table or a stored role table that is
   * malformed, since it reads those whole.
   */
  diverged(catalog: Catalog, grants: unknown, options?: ClockOptions): Diverged | undefined;
  /**
   * Validates one whole grants object against every rule of its form, where the application
   * receives one: throws `ERR_AUTHZ_MALFORMED` for a rule that fails, `ERR_AUTHZ_GRANTS_FORMAT`
   * for another revision, `ERR_AUTHZ_GRANTS_EARLY` when the clock reads earlier than the issue.
   */
  assertGrants(catalog: Catalog, value: unknown, options?: ClockOptions): void;
  issueGrants(catalog: Catalog, read: SubjectStatements, options?: IssueGrantsOptions): unknown;
  /** Every problem of the statement, none when it may be written. */
  validateStatement(
    catalog: Catalog,
    value: unknown,
    options?: ValidateStatementOptions,
  ): readonly Issue[];
  /** Every problem of the stored role, none when it may be written. */
  validateRole(catalog: Catalog, value: unknown, options?: ValidateOptions): readonly Issue[];
  placeChain(key: string): string[];
  placeRange(key: string): { after: string; before: string };
}
