import type { DatabaseSync } from "node:sqlite";
import { text } from "../../storage/rows.ts";

export function createWordPressTables(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE posts (
      id INTEGER PRIMARY KEY,
      author TEXT REFERENCES users (id),
      status TEXT NOT NULL CHECK (status IN ('publish', 'future', 'draft', 'pending', 'private')),
      title TEXT NOT NULL
    );
    CREATE TABLE options (
      name TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    INSERT INTO options (name, value) VALUES ('default_role', 'subscriber');
  `);
}

export function defaultRole(db: DatabaseSync): string {
  const row = db.prepare("SELECT value FROM options WHERE name = 'default_role'").get();
  if (row === undefined) throw new Error("No default role is set.");
  return text(row, "value");
}
