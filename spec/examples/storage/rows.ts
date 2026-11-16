import type { Statement, StatementKind, StoredRole } from "unauth/z";

export type Row = Record<string, unknown>;

export function text(row: Row, column: string): string {
  const value = row[column];
  if (typeof value !== "string") throw new TypeError(`Column ${column} holds no text.`);
  return value;
}

export function integer(row: Row, column: string): number | undefined {
  const value = row[column];
  if (value === null || value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value)) {
    throw new TypeError(`Column ${column} holds no integer.`);
  }
  return value;
}

export function statementOf(row: Row): Statement {
  const expiresAt = integer(row, "expires_at");
  return {
    kind: kindOf(text(row, "kind")),
    subject: text(row, "subject"),
    value: text(row, "value"),
    place: text(row, "place"),
    ...(expiresAt === undefined ? {} : { expiresAt }),
  };
}

export function roleOf(row: Row, column = "name"): StoredRole {
  const entries: unknown = JSON.parse(text(row, "entries"));
  if (!Array.isArray(entries) || !entries.every((entry) => typeof entry === "string")) {
    throw new TypeError("The entries of a stored role are not a list of strings.");
  }
  return { name: text(row, column), entries };
}

const KINDS: readonly StatementKind[] = ["allow", "assign", "deny", "exclude"];

function kindOf(value: string): StatementKind {
  const kind = KINDS.find((known) => known === value);
  if (kind === undefined) throw new TypeError(`Unknown statement kind ${value}.`);
  return kind;
}
