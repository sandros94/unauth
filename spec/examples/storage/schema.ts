import type { DatabaseSync } from "node:sqlite";

export function createTables(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY COLLATE BINARY
    );
    CREATE TABLE statements (
      kind TEXT NOT NULL CHECK (kind IN ('allow', 'assign', 'deny', 'exclude')),
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
      entries TEXT NOT NULL,
      gives TEXT NOT NULL,
      catalog TEXT NOT NULL
    );
    CREATE TABLE sessions (
      token_hash TEXT PRIMARY KEY,
      id TEXT NOT NULL,
      subject TEXT NOT NULL COLLATE BINARY,
      data TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      expires_at INTEGER
    );
    CREATE INDEX sessions_by_subject ON sessions (subject);
  `);
}
