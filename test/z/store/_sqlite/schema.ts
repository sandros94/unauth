import type { Statement, StatementKind, StoredRole } from "../../../../src/z/types.ts";
import type { CountedDatabase, Row } from "./database.ts";

/** Keys, subjects, values and names compare byte by byte: every such column is `BINARY`. */
export function createSchema(db: CountedDatabase): void {
  db.define(
    "schema",
    `CREATE TABLE memberships (
      subject TEXT NOT NULL COLLATE BINARY,
      grp TEXT NOT NULL COLLATE BINARY,
      PRIMARY KEY (subject, grp)
    );
    CREATE TABLE teams (
      id TEXT PRIMARY KEY COLLATE BINARY,
      parent TEXT COLLATE BINARY
    );
    CREATE TABLE statements (
      kind TEXT NOT NULL COLLATE BINARY,
      subject TEXT NOT NULL COLLATE BINARY,
      value TEXT NOT NULL COLLATE BINARY,
      place TEXT NOT NULL COLLATE BINARY,
      expires_at INTEGER,
      PRIMARY KEY (kind, subject, value, place)
    );
    CREATE INDEX statements_by_subject ON statements (subject, place);
    CREATE INDEX statements_by_place ON statements (place);
    CREATE TABLE roles (
      name TEXT PRIMARY KEY COLLATE BINARY,
      entries TEXT NOT NULL
    );
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY COLLATE BINARY,
      subject TEXT NOT NULL COLLATE BINARY,
      grants TEXT NOT NULL
    );
    CREATE TABLE session_heads (
      id TEXT PRIMARY KEY COLLATE BINARY,
      subject TEXT NOT NULL COLLATE BINARY,
      head TEXT NOT NULL
    );
    CREATE TABLE session_entries (
      session TEXT NOT NULL COLLATE BINARY,
      name TEXT NOT NULL COLLATE BINARY,
      entry TEXT NOT NULL,
      PRIMARY KEY (session, name)
    );
    CREATE TABLE repos (
      org TEXT NOT NULL COLLATE BINARY,
      name TEXT NOT NULL COLLATE BINARY,
      visibility TEXT NOT NULL,
      PRIMARY KEY (org, name)
    );`,
  );
}

export function text(row: Row, column: string): string {
  const value = row[column];
  if (typeof value !== "string") throw new TypeError(`Expected text in column ${column}.`);
  return value;
}

/** A statement from a row with the columns `kind`, `subject`, `value`, `place`, `expires_at`. */
export function statementOf(row: Row): Statement {
  const expiresAt = row.expires_at;
  return {
    kind: kindOf(text(row, "kind")),
    subject: text(row, "subject"),
    value: text(row, "value"),
    place: text(row, "place"),
    ...(typeof expiresAt === "number" && { expiresAt }),
  };
}

/** A stored role from a row with the columns `name` and `entries`. */
export function roleOf(row: Row): StoredRole {
  const entries: unknown = JSON.parse(text(row, "entries"));
  if (!Array.isArray(entries) || !entries.every((entry) => typeof entry === "string")) {
    throw new TypeError("The entries of a stored role are not a list of strings.");
  }
  return { name: text(row, "name"), entries };
}

/** Writes statements as they are, with no question asked first: for seeding only. */
export function insertStatements(db: CountedDatabase, statements: readonly Statement[]): void {
  for (const { kind, subject, value, place = "/", expiresAt } of statements) {
    db.write(
      "statements.insert",
      `INSERT INTO statements (kind, subject, value, place, expires_at)
       VALUES ($kind, $subject, $value, $place, $expires)`,
      { kind, subject, value, place, expires: expiresAt ?? null },
    );
  }
}

/** Every statement and every stored role, for comparing an answer with the whole store. */
export function everything(db: CountedDatabase): { statements: Statement[]; roles: StoredRole[] } {
  return {
    statements: db
      .read("statements.all", "SELECT kind, subject, value, place, expires_at FROM statements")
      .map(statementOf),
    roles: db.read("roles.all", "SELECT name, entries FROM roles").map(roleOf),
  };
}

const KINDS: readonly StatementKind[] = ["allow", "assign", "deny", "exclude"];

function kindOf(value: string): StatementKind {
  const kind = KINDS.find((known) => known === value);
  if (kind === undefined) throw new TypeError(`Unknown statement kind ${value}.`);
  return kind;
}
