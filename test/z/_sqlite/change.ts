import type { Catalog } from "../../../src/z/catalog.ts";
import { type Change, checkChange, checkGenesis } from "../../../src/z/change.ts";
import type { Statement } from "../../../src/z/types.ts";
import type { CountedDatabase } from "./database.ts";
import { type Gathered, gather } from "./gather.ts";
import { statementOf } from "./schema.ts";

/** Who asks for a change, and when, in seconds. */
export interface Author {
  subject: string;
  at: number;
}

/**
 * The one read a change is checked against: what the author and its groups hold on the chain of
 * the place and under it, the stored roles the change names, and the root's permanent allows of
 * `*` when the change touches one.
 */
export function readForChange(db: CountedDatabase, author: Author, change: Change): Gathered {
  const at = change.action === "define" ? change.role.home : change.statement.place;
  const place = at ?? "/";
  return gather(db, `change.${change.action}`, {
    subject: author.subject,
    at: author.at,
    chain: [place],
    under: [place],
    roles: namedBy(change),
    managers: change.action !== "define" && isRootManagement(change.statement),
  });
}

/** Checks a change against what {@link readForChange} returned. */
export function checkRead(catalog: Catalog, author: Author, change: Change, read: Gathered): void {
  checkChange(catalog, change, {
    author: author.subject,
    groups: read.groups,
    statements: read.statements,
    roles: read.roles,
    ...(change.action !== "define" &&
      isRootManagement(change.statement) && { managers: read.managers }),
    now: () => author.at * 1000,
  });
}

/** Reads, checks and writes a change in one transaction, returning what the check read. */
export function applyChange(
  db: CountedDatabase,
  catalog: Catalog,
  author: Author,
  change: Change,
): Gathered {
  return db.transaction(() => {
    const read = readForChange(db, author, change);
    checkRead(catalog, author, change, read);
    writeChange(db, change);
    return read;
  });
}

/** Reads the root's permanent allows of `*`, checks genesis and writes it, in one transaction. */
export function applyGenesis(
  db: CountedDatabase,
  catalog: Catalog,
  statement: Statement,
  at: number,
): void {
  db.transaction(() => {
    const managers = db
      .read(
        "genesis",
        `SELECT kind, subject, value, place, expires_at FROM statements
         WHERE kind = 'allow' AND value = '*' AND place = '/' AND expires_at IS NULL`,
      )
      .map(statementOf);
    checkGenesis(catalog, statement, { managers, now: () => at * 1000 });
    writeChange(db, { action: "place", statement });
  });
}

/** Writes a change the engine accepted: a placement replaces the end of its identity. */
export function writeChange(db: CountedDatabase, change: Change): void {
  if (change.action === "define") {
    const { name, home = "/", entries } = change.role;
    db.write(
      "roles.define",
      `INSERT INTO roles (name, home, entries) VALUES ($name, $home, $entries)
       ON CONFLICT (name, home) DO UPDATE SET entries = excluded.entries`,
      { name, home, entries: JSON.stringify(entries) },
    );
    return;
  }
  const { kind, subject, value, place = "/", expiresAt } = change.statement;
  if (change.action === "remove") {
    db.write(
      "statements.remove",
      `DELETE FROM statements
       WHERE kind = $kind AND subject = $subject AND value = $value AND place = $place`,
      { kind, subject, value, place },
    );
    return;
  }
  db.write(
    "statements.place",
    `INSERT INTO statements (kind, subject, value, place, expires_at)
     VALUES ($kind, $subject, $value, $place, $expires)
     ON CONFLICT (kind, subject, value, place) DO UPDATE SET expires_at = excluded.expires_at`,
    { kind, subject, value, place, expires: expiresAt ?? null },
  );
}

function isRootManagement(statement: Statement): boolean {
  return statement.kind === "allow" && statement.value === "*" && (statement.place ?? "/") === "/";
}

function namedBy(change: Change): string[] {
  if (change.action === "define") {
    const references = change.role.entries
      .map((entry) => (entry.startsWith("-") ? entry.slice(1) : entry))
      .filter((entry) => entry !== "*" && !entry.includes(":"));
    return [change.role.name, ...references];
  }
  return change.statement.kind === "assign" ? [change.statement.value] : [];
}
