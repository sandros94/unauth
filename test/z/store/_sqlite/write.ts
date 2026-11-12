import { ask } from "../../../../src/z/ask.ts";
import type { Catalog } from "../../../../src/z/catalog.ts";
import type { Statement, StoredRole } from "../../../../src/z/types.ts";
import { assertRole, assertStatement } from "../../../../src/z/validate.ts";
import type { CountedDatabase } from "./database.ts";
import { type Gathered, gather } from "./gather.ts";

/** What the application writes: a statement placed or removed, or a stored role defined or edited. */
export type Write =
  | { action: "place" | "remove"; statement: Statement }
  | { action: "define"; role: StoredRole };

/** Who asks for a write, and when, in seconds. */
export interface Author {
  subject: string;
  at: number;
}

/** The application's own refusal: the author does not hold the permission it asks for a write. */
export class Forbidden extends Error {
  constructor(readonly place: string) {
    super("The author may not change access here.");
  }
}

/** The permission of the forge's own that it asks before every write. */
export const ACCESS = "access:manage";

/**
 * The one read a write needs: the statements about the author and its groups on the chain of the
 * place, and the stored roles the write names, with the roles those reference.
 */
export function readForWrite(db: CountedDatabase, author: Author, write: Write): Gathered {
  return gather(db, `write.${write.action}`, {
    subject: author.subject,
    at: author.at,
    chain: [placeOf(write)],
    under: [],
    roles: namedBy(write),
  });
}

/**
 * What the forge asks before it writes: `access:manage` at the place of the write, the root for a
 * stored role, then whether what it writes is valid for the catalog. A removal is not validated,
 * so that what went inert stays removable.
 */
export function checkWrite(catalog: Catalog, author: Author, write: Write, read: Gathered): void {
  const place = placeOf(write);
  const now = () => author.at * 1000;
  if (!ask(catalog, read, { permission: ACCESS, place }, { now }).allowed) {
    throw new Forbidden(place);
  }
  if (write.action === "define") assertRole(catalog, write.role, { roles: read.roles });
  else if (write.action === "place") {
    assertStatement(catalog, write.statement, { roles: read.roles, now });
  }
}

/** Reads, checks and writes in one transaction, returning what the check read. */
export function applyWrite(
  db: CountedDatabase,
  catalog: Catalog,
  author: Author,
  write: Write,
): Gathered {
  return db.transaction(() => {
    const read = readForWrite(db, author, write);
    checkWrite(catalog, author, write, read);
    writeTo(db, write);
    return read;
  });
}

/** Writes what the check accepted: a placement replaces the end of its identity. */
export function writeTo(db: CountedDatabase, write: Write): void {
  if (write.action === "define") {
    const { name, entries } = write.role;
    db.write(
      "roles.define",
      `INSERT INTO roles (name, entries) VALUES ($name, $entries)
       ON CONFLICT (name) DO UPDATE SET entries = excluded.entries`,
      { name, entries: JSON.stringify(entries) },
    );
    return;
  }
  const { kind, subject, value, place = "/", expiresAt } = write.statement;
  if (write.action === "remove") {
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

function placeOf(write: Write): string {
  return write.action === "define" ? "/" : (write.statement.place ?? "/");
}

function namedBy(write: Write): string[] {
  if (write.action === "define") {
    const references = write.role.entries
      .map((entry) => (entry.startsWith("-") ? entry.slice(1) : entry))
      .filter((entry) => entry !== "*" && !entry.includes(":"));
    return [write.role.name, ...references];
  }
  return write.statement.kind === "assign" ? [write.statement.value] : [];
}
