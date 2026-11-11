/** What a statement asserts about its subject. */
export type StatementKind = "allow" | "assign" | "deny" | "exclude";

/**
 * One stored assertion about one subject at one place, in the shape the model gives it. `kind`,
 * `subject`, `value` and `place` identify a statement: a store keeps one per identity, and only
 * `expiresAt` ever changes.
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

/** A role defined in data, beside the presets of the catalog. */
export interface StoredRole {
  name: string;
  /** The place it is defined at: assignable there and under it. Absent is the root. */
  home?: string;
  /** Permissions, names of other roles, and either one prefixed with `-` to exclude it. */
  entries: readonly string[];
}

/** "May this subject do this, here?", asked of statements: one permission at one place. */
export interface Question<TPermission extends string = string> {
  subject: string;
  /** Every group the subject belongs to. A group left out is a deny silently missed. */
  groups?: readonly string[];
  /** The permission asked. Never a wildcard. */
  permission: TPermission;
  /** The key of the place asked about. Absent is the root. */
  place?: string;
}

/** A {@link Question} asked of grants, which already hold whom they were issued for. */
export type GrantsQuestion<TPermission extends string = string> = Omit<
  Question<TPermission>,
  "subject" | "groups"
>;

/** The answer to a question. */
export interface Decision {
  allowed: boolean;
  /**
   * `false` only when grants do not speak for the place asked: then nothing was allowed and nothing
   * was denied, and the statements or another set of grants must be asked. Always `true` for a
   * question asked of statements.
   */
  covered: boolean;
  /**
   * The statement that decided: the deny that blocked, or the allow or assignment that gave.
   * Absent when nothing gives the permission, and when the place is not covered. Grants do not
   * carry `subject`.
   */
  by?: Omit<Statement, "subject"> & { subject?: string };
}

/**
 * What the statements about a subject amount to, carried outside them: in a session cookie, a
 * token, a server-side record. The engine reads the members below and ignores any other, so an
 * application may add its own beside them.
 */
export interface Grants {
  /** The revision of this format. */
  v: "1";
  /** The fingerprint of the catalog they were issued for. */
  ct: string;
  /** When they were issued, in seconds. */
  at: number;
  /** The places they speak for. Absent is the root, which is everything. */
  bs?: string[];
  /** The place table the items index. */
  pl?: string[];
  /** The role table: what each stored role resolved to when the grants were issued. */
  rl?: string[][];
  /** The entries, by value: a permission as written, a preset name, or `#` and a row of `rl`. */
  nt: Record<string, GrantsEntry>;
  [member: string]: unknown;
}

/** What is given (`a`), denied (`d`) and taken out (`x`) under one value. */
export interface GrantsEntry {
  a?: GrantsItem[];
  d?: GrantsItem[];
  x?: GrantsItem[];
}

/** Where, until when, and in which bundle. Trailing `null`s may be left out. */
export type GrantsItem = [place?: number | null, end?: number | null, bundle?: number | null];
