import type { KnownUnauthErrorCode } from "../../error.ts";
import type { CatalogData } from "../catalog.ts";
import type { Statement, StatementIdentity, StoredRole } from "../types.ts";
import type { Question } from "./engine.ts";

/** The guarantees of the model, by the identifier its Section 4 gives them. */
export type RuleId = "G1" | "G2" | "G3" | "G4" | "G5" | "G6" | "G7" | "G8" | "G9";

/** What a step expects in place of an answer: the code of the error the engine must throw. */
export type ScenarioRefusal = Extract<KnownUnauthErrorCode, `ERR_AUTHZ_${string}`>;

/**
 * One case: what is stored, then what happens, each step with the answer the model requires.
 * Steps run in order over the same statements, so a scenario lets time pass and data change.
 */
export interface Scenario {
  /** A stable name: `"exclusion/narrower-allow-gives-back"`. */
  id: string;
  /** What a real deployment meets, in plain words. */
  title: string;
  /** The rows of the model it proves: each must have a step whose answer would differ without it. */
  proves: readonly RuleId[];
  catalog: CatalogData;
  statements?: readonly Statement[];
  /** The stored roles, handed whole to every call that takes them, two of one name included. */
  roles?: readonly StoredRole[];
  steps: readonly ScenarioStep[];
}

/** One step. `at` is the time it happens, in seconds since the epoch. */
export type ScenarioStep = AskStep | HandStep | IssueStep | ReadStep | WriteStep;

/** A question as the application meets it: who asks, and which groups they are in at that moment. */
export interface ScenarioQuestion extends Question {
  subject: string;
  /** Every group the subject belongs to: the statements about them apply to it. */
  groups?: readonly string[];
}

/** What an ask may also check: grants issued at an earlier time must answer now as the statements do. */
export interface FromGrants {
  /** Issue the subject's grants at this time, from the same statements, and read them at `at`. */
  issuedAt?: number;
  /** The bases of those grants. @default the root */
  bases?: readonly string[];
  /** What the grants must answer, when not the same as `expect`: a place outside `bases` is `"not-covered"`. */
  fromGrants?: "allowed" | "denied" | "not-covered" | ScenarioRefusal;
}

/**
 * A question asked of the statements as they stand. The runner plays the application: it hands the
 * engine the statements about the subject and its groups, all of them, then only those the
 * question needs.
 */
export interface AskStep extends FromGrants {
  step: "ask";
  at: number;
  question: ScenarioQuestion;
  expect: "allowed" | "denied" | ScenarioRefusal;
}

/**
 * A question asked of exactly the statements listed, whatever the application keeps: what an
 * engine makes of statements about a subject the asker is not, or of a group's left out.
 */
export interface HandStep extends FromGrants {
  step: "hand";
  at: number;
  subject: string;
  statements: readonly Statement[];
  question: Question;
  expect: "allowed" | "denied" | ScenarioRefusal;
}

/** Issues grants from the statements as they stand and keeps them under a name for later `read` steps. */
export interface IssueStep {
  step: "issue";
  at: number;
  /** The name later steps read them by. */
  as: string;
  subject: string;
  groups?: readonly string[];
  bases?: readonly string[];
  /** When issuing itself must be refused. */
  expect?: ScenarioRefusal;
}

/** Reads grants issued earlier: they answer from what they hold, whatever was written since. */
export interface ReadStep {
  step: "read";
  at: number;
  /** One set by name, or several read together. */
  grants: string | readonly string[];
  question: Question;
  expect: "allowed" | "denied" | "not-covered" | ScenarioRefusal;
}

/** What the application writes to its own storage: a grant, a revocation, a move, an edited role. */
export interface WriteStep {
  step: "write";
  /** Statements stored, each replacing the one of its identity. */
  save?: readonly Statement[];
  remove?: readonly StatementIdentity[];
  /** The stored roles after the write, replacing all of them. */
  roles?: readonly StoredRole[];
}

/** A catalog and whether an engine must accept it. */
export interface CatalogCase {
  id: string;
  title: string;
  /** Possibly not a catalog at all: the point of some cases. */
  catalog: unknown;
  expect: "accepted" | "ERR_AUTHZ_CATALOG_INVALID";
  /** The fingerprint an accepted catalog must have, computed apart from any engine. */
  fingerprint?: string;
}

/** A key and what an engine must make of it. */
export interface PlaceCase {
  id: string;
  key: string;
  expect: "canonical" | "ERR_AUTHZ_MALFORMED";
  /** For a canonical key: the places covering it, itself first, the root last. */
  chain?: readonly string[];
  /** For a canonical key: the bounds every place under it lies between. */
  range?: { after: string; before: string };
}

/**
 * Grants written by hand, as another engine or a tampering client would hand them over, and what
 * a read must make of them.
 */
export interface GrantsCase {
  id: string;
  title: string;
  catalog: CatalogData;
  /** Possibly not grants at all. The string `"$ct"` as its `ct` stands for the fingerprint of `catalog`. */
  grants: unknown;
  at: number;
  question: Question;
  expect: "allowed" | "denied" | "not-covered" | ScenarioRefusal;
}

/** The code validation reports a problem of the value with. */
export type IssueCode = Extract<
  ScenarioRefusal,
  | "ERR_AUTHZ_MALFORMED"
  | "ERR_AUTHZ_PERMISSION_UNKNOWN"
  | "ERR_AUTHZ_PLACE_OUTSIDE"
  | "ERR_AUTHZ_ROLE_INVALID"
  | "ERR_AUTHZ_STATEMENT_ENDED"
>;

/** One problem a case expects validation to report, compared on its code and path. */
export interface ExpectedIssue {
  code: IssueCode;
  path: readonly (string | number)[];
}

/**
 * What validating must give: every problem of the value, in any order, none when it is valid. A
 * code alone is what validation must throw, for a problem of what is handed in beside the value.
 */
export type ValidationExpect = readonly ExpectedIssue[] | ScenarioRefusal;

/** A statement an application is about to write, and what validating it must give. */
export interface StatementCase {
  id: string;
  title: string;
  catalog: CatalogData;
  /** When it is validated, in seconds since the epoch: an end not later than this is refused. */
  at: number;
  /** The stored roles handed in with it. */
  roles?: readonly StoredRole[];
  /** Possibly not a statement at all: the point of some cases. */
  statement: unknown;
  expect: ValidationExpect;
}

/** A stored role an application is about to write, and what validating it must give. */
export interface RoleCase {
  id: string;
  title: string;
  catalog: CatalogData;
  /** The other stored roles handed in with it. */
  roles?: readonly StoredRole[];
  /** Possibly not a role at all: the point of some cases. */
  role: unknown;
  expect: ValidationExpect;
}

/** Every kind of case, as `runConformance` runs an engine against them. */
export interface Cases {
  /** Situations with steps: questions, grants issued and read, writes, time passing. */
  scenarios: readonly Scenario[];
  /** Catalogs an engine must accept, with their fingerprint, or refuse. */
  catalogCases: readonly CatalogCase[];
  /** Keys an engine must take as canonical, with their chain and range, or refuse. */
  placeCases: readonly PlaceCase[];
  /** Grants written by hand and what a read must make of them. */
  grantsCases: readonly GrantsCase[];
  /** Statements and the problems validating them must report. */
  statementCases: readonly StatementCase[];
  /** Stored roles and the problems validating them must report. */
  roleCases: readonly RoleCase[];
}

/** What a run found. */
export interface ConformanceReport {
  /** The ids of the cases that passed. */
  passed: string[];
  failed: ConformanceFailure[];
}

/** One case that answered otherwise than the model requires. */
export interface ConformanceFailure {
  /** The id of the scenario or case. */
  id: string;
  /** The index of the step, for a scenario. */
  step?: number;
  /**
   * What the engine was handed when it failed: every statement that applies to the subject, or
   * only those the call needs. Absent for a `hand` step, which hands what it lists.
   */
  given?: "everything" | "needed";
  expected: unknown;
  received: unknown;
}
