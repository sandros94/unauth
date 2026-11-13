import type { UnauthErrorCauseMap } from "../error.ts";

/** What a statement asserts about its subject. */
export type StatementKind = "allow" | "assign" | "deny" | "exclude";

/**
 * One stored assertion about one subject at one place, in the shape the model gives it. `kind`,
 * `subject`, `value` and `place` identify a statement: the application keeps one per identity,
 * and only `expiresAt` ever changes.
 */
export interface Statement {
  kind: StatementKind;
  /** Whom it is about: the identifier of a subject or of a group. */
  subject: string;
  /** A permission, wildcards allowed (`report:*`, `*:read`, `*`), or the name of a role for `assign`. */
  value: string;
  /** The key of the place it applies at and under. Absent is the root. */
  place?: string;
  /** When it ends, in seconds since the epoch. Absent never ends. */
  expiresAt?: number;
}

/** What identifies a {@link Statement}. */
export type StatementIdentity = Pick<Statement, "kind" | "subject" | "value" | "place">;

/**
 * A role kept in data, beside the presets of the catalog: a name and its entries, assignable at
 * any place. A preset of the same name wins over it wherever the name is read.
 */
export interface StoredRole {
  name: string;
  /** Permissions, names of other roles, and either one prefixed with `-` to exclude it. */
  entries: readonly string[];
}

/**
 * What the application read for one subject: every statement that applies to it, those about the
 * subject itself and those about each group it belongs to, with the stored roles they assign. A
 * statement whose `subject` is `subject` is about the subject itself, any other about one of its
 * groups, and statements with the same `subject` are about the same group. A group whose
 * statements are left out does not count, and a statement about a subject it does not belong to
 * counts as a group's: what is handed over must be whole, and nothing more.
 */
export interface SubjectStatements<TStatement extends Statement = Statement> {
  /** The identifier of whom the statements were read for. */
  subject: string;
  /** Every statement that applies to the subject: those about it and those about the groups it belongs to. */
  statements: readonly TStatement[];
  /** The stored roles those statements assign, with the roles they reference. */
  roles?: readonly StoredRole[];
}

/** "May the subject do this, here?": one permission at one place. */
export interface Question<TPermission extends string = string> {
  /** The permission asked. Never a wildcard. */
  permission: TPermission;
  /** The key of the place asked about. Absent is the root. */
  place?: string;
}

/** Options of a question, `ask` and `could`, and of `diverged`. */
export interface QuestionOptions {
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
}

/**
 * The answer to a question. `TBy` is what can decide: the statement type handed to `ask`, or for
 * grants a statement without its subject.
 */
export interface Decision<TBy = Omit<Statement, "subject"> & { subject?: string }> {
  allowed: boolean;
  /**
   * `false` only when grants do not speak for the place asked: then nothing was allowed and nothing
   * was denied, and the statements or another set of grants must be asked. Always `true` for a
   * question asked of statements.
   */
  covered: boolean;
  /**
   * What decided: the deny that blocked, or the allow or assignment that gave. Asked of
   * statements, the very object handed in. Absent when nothing gives the permission, and when the
   * place is not covered.
   */
  by?: TBy;
  /**
   * What of the grants read differs from the catalog in force, present whenever something does,
   * whatever the answer, not covered included: see {@link Diverged}. Absent when every set read
   * was issued under this very catalog. Never set by a question asked of statements.
   */
  diverged?: Diverged;
}

/**
 * What of grants differs from the catalog they are read under. A read still answers: patterns,
 * implications and places take their meaning from the catalog in force, and a copy of a preset is
 * read as it was at issue. It is the application's signal to issue the grants again, when it no
 * longer accepts what they give.
 */
export interface Diverged {
  /**
   * The segments of the fingerprint that differ, at least one, in this order: `permissions` covers
   * the permissions, the implications and the places, `presets` the presets.
   */
  segments: ("permissions" | "presets")[];
  /** The concrete permissions the grants name that the catalog does not declare, sorted by bytes. */
  permissions: string[];
  /**
   * The roles the grants hold whose name no longer means the same, sorted by bytes: a copy of a
   * preset the catalog no longer declares, or declares with other entries, and a stored role held
   * under a name the catalog now declares as a preset with other entries. Entries are compared as
   * sets. Either keeps giving what it gave at issue, while the statements would now read the
   * catalog's preset.
   */
  presets: string[];
}

/** The codes a validation reports a problem of the value with. */
type ValidationIssueCode =
  | "ERR_AUTHZ_MALFORMED"
  | "ERR_AUTHZ_PERMISSION_UNKNOWN"
  | "ERR_AUTHZ_PLACE_OUTSIDE"
  | "ERR_AUTHZ_ROLE_INVALID"
  | "ERR_AUTHZ_STATEMENT_ENDED";

/**
 * One problem of a statement or a stored role being validated, as plain data that survives JSON:
 * the `code`, `message` and `cause` of the `UnauthError` an assertion throws for it, `cause` typed
 * by `code`, and the `path` of the member it is about, for a form to show it there: `["kind"]`,
 * `["subject"]`, `["value"]`, `["place"]` or `["expiresAt"]` for a statement, `["name"]`,
 * `["entries"]` or `["entries", index]` for a role, `[]` for a value that is not an object.
 */
export type ValidationIssue = {
  [TCode in ValidationIssueCode]: {
    code: TCode;
    path: (string | number)[];
    message: string;
    cause: UnauthErrorCauseMap[TCode];
  };
}[ValidationIssueCode];

/**
 * A part of grants that can travel by name instead of as a copy: `presets`, the definitions of the
 * presets they name, then read from the catalog in force, as it declares them when read.
 */
export type GrantsPart = "presets";

/**
 * What the statements about a subject amount to, carried outside them: in a session cookie, a
 * token, a server-side record. The engine reads the members below and ignores any other, so an
 * application may add its own beside them.
 */
export interface Grants {
  /** The revision of this format. */
  v: "1";
  /** The fingerprint of the catalog they were issued under, its two segments joined by `.`. */
  ct: string;
  /** When they were issued, in seconds. */
  at: number;
  /** The places they speak for. Absent is the root, which is everything. */
  bs?: string[];
  /** The place table the items index. */
  pl?: string[];
  /**
   * The permission table: every concrete permission these grants name, each once, in an entry or in
   * a definition. Written only beside `ps` or `sr`. It is not the catalog's list: a position is a
   * position in `pm`, never in the catalog.
   */
  pm?: string[];
  /** The copies of the presets these grants name, by name. Absent when presets travel by name. */
  ps?: Record<string, GrantsRoleEntry[]>;
  /** The definitions of the stored roles these grants name, by name. */
  sr?: Record<string, GrantsRoleEntry[]>;
  /**
   * The entries, by value: a pattern as written, a role name, or a permission, by its name without
   * `pm` and by its position in `pm`, as `"2"`, with one.
   */
  nt: Record<string, GrantsEntry>;
  [member: string]: unknown;
}

/**
 * One entry of a role's definition in grants: a concrete permission as its position in `pm`, an
 * excluded one as `-` and that position (`"-0"`), anything else as written in the role.
 */
export type GrantsRoleEntry = string | number;
/** What is given (`a`), denied (`d`) and taken out (`x`) under one value. */
export interface GrantsEntry {
  a?: GrantsItem[];
  d?: GrantsItem[];
  x?: GrantsItem[];
}

/** Where, until when, and in which bundle. Trailing `null`s may be left out. */
export type GrantsItem = [place?: number | null, end?: number | null, bundle?: number | null];
