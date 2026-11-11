import type { KnownUnauthErrorCode, UnauthErrorCauseMap } from "../../error.ts";
import type { CatalogData, defineCatalog } from "../catalog.ts";
import type { Change, checkChange, checkGenesis } from "../change.ts";
import type { decide } from "../decide.ts";
import type { issueGrants, readGrants } from "../grants.ts";
import type { placeChain, placeRange } from "../place.ts";
import type {
  GrantsQuestion,
  Question,
  Statement,
  StatementIdentity,
  StoredRole,
} from "../types.ts";

/** The guarantees and rules of the model, by the identifier its Section 4 gives them. */
export type RuleId =
  | "D1"
  | "D2"
  | "D3"
  | "D4"
  | "D5"
  | "D6"
  | "D7"
  | "D8"
  | "D9"
  | "A1"
  | "A2"
  | "A3"
  | "A4"
  | "A5"
  | "A6"
  | "A7"
  | "G1"
  | "G2"
  | "G3"
  | "G4";

/** What a step expects in place of an answer: the code of the error the engine must throw. */
export type ScenarioRefusal = Extract<KnownUnauthErrorCode, `ERR_AUTHZ_${string}`>;

/** A reason `ERR_AUTHZ_CHANGE_REFUSED` names. */
export type ChangeReason = UnauthErrorCauseMap["ERR_AUTHZ_CHANGE_REFUSED"]["reasons"][number];

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
  roles?: readonly StoredRole[];
  steps: readonly ScenarioStep[];
}

/** One step. `at` is the time it happens, in seconds since the epoch. */
export type ScenarioStep = AskStep | IssueStep | ReadStep | ChangeStep | GenesisStep | WriteStep;

/** A question asked of the statements as they stand. */
export interface AskStep {
  step: "ask";
  at: number;
  question: Question;
  expect: "allowed" | "denied" | ScenarioRefusal;
  /**
   * Also issue the subject's grants at this earlier time, from the statements as they stand, and
   * read them at `at`: grants issued then must answer now as the statements do.
   */
  issuedAt?: number;
  /** The bases of those grants. @default the root */
  bases?: readonly string[];
  /** What the grants must answer, when not the same as `expect`: a place outside `bases` is `"not-covered"`. */
  fromGrants?: "allowed" | "denied" | "not-covered" | ScenarioRefusal;
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
  question: GrantsQuestion;
  expect: "allowed" | "denied" | "not-covered" | ScenarioRefusal;
}

/** A change asked by an author. An accepted one is applied to the statements of the scenario. */
export interface ChangeStep {
  step: "change";
  at: number;
  author: string;
  groups?: readonly string[];
  change: Change;
  expect: "accepted" | ScenarioRefusal;
  /** With `ERR_AUTHZ_CHANGE_REFUSED`: the reasons it must name, no more and no fewer, in any order. */
  reasons?: readonly ChangeReason[];
}

/** The first change of an application: placing the first permanent manager. */
export interface GenesisStep {
  step: "genesis";
  at: number;
  statement: Statement;
  expect: "accepted" | ScenarioRefusal;
  /** With `ERR_AUTHZ_CHANGE_REFUSED`: the reasons it must name, no more and no fewer, in any order. */
  reasons?: readonly ChangeReason[];
}

/** What the application rewrites on its own storage, unchecked: a move, a cleanup, a deleted role. */
export interface WriteStep {
  step: "write";
  /** Statements stored, each replacing the one of its identity. */
  save?: readonly Statement[];
  remove?: readonly StatementIdentity[];
  /** The stored roles after the rewrite, replacing all of them. */
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
  question: GrantsQuestion;
  expect: "allowed" | "denied" | "not-covered" | ScenarioRefusal;
}

/** Every kind of case, as {@link Engine} functions are run against them. */
export interface Cases {
  /** Situations with steps: questions, grants issued and read, changes, time passing. */
  scenarios: readonly Scenario[];
  /** Catalogs an engine must accept, with their fingerprint, or refuse. */
  catalogCases: readonly CatalogCase[];
  /** Keys an engine must take as canonical, with their chain and range, or refuse. */
  placeCases: readonly PlaceCase[];
  /** Grants written by hand and what a read must make of them. */
  grantsCases: readonly GrantsCase[];
}

/** The functions of an engine the cases call: those of `unauth/z`, or others with the same signatures. */
export interface Engine {
  defineCatalog: typeof defineCatalog;
  decide: typeof decide;
  issueGrants: typeof issueGrants;
  readGrants: typeof readGrants;
  checkChange: typeof checkChange;
  checkGenesis: typeof checkGenesis;
  placeChain: typeof placeChain;
  placeRange: typeof placeRange;
}

/** What a run found. */
export interface ValidationReport {
  /** The ids of the cases that passed. */
  passed: string[];
  failed: ValidationFailure[];
}

/** One case that answered otherwise than the model requires. */
export interface ValidationFailure {
  /** The id of the scenario or case. */
  id: string;
  /** The index of the step, for a scenario. */
  step?: number;
  /** Which input the engine was given when it failed: everything stored, or only what the call needs. */
  given?: "everything" | "needed";
  expected: unknown;
  received: unknown;
}
