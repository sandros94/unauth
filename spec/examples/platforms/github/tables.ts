import type { DatabaseSync } from "node:sqlite";

export function createGitHubTables(db: DatabaseSync): void {
  db.exec(`
    CREATE TABLE memberships (
      member TEXT NOT NULL COLLATE BINARY,
      grp TEXT NOT NULL COLLATE BINARY,
      PRIMARY KEY (member, grp)
    );
    CREATE INDEX memberships_by_group ON memberships (grp);
    CREATE TABLE enterprises (
      slug TEXT PRIMARY KEY COLLATE BINARY
    );
    CREATE TABLE orgs (
      login TEXT PRIMARY KEY COLLATE BINARY,
      enterprise TEXT REFERENCES enterprises (slug),
      outside_collaborators TEXT NOT NULL DEFAULT 'admins'
        CHECK (outside_collaborators IN ('admins', 'owners'))
    );
    CREATE TABLE teams (
      id TEXT PRIMARY KEY COLLATE BINARY,
      org TEXT NOT NULL REFERENCES orgs (login),
      slug TEXT NOT NULL COLLATE BINARY,
      parent TEXT REFERENCES teams (id),
      UNIQUE (org, slug)
    );
    CREATE TABLE repos (
      org TEXT NOT NULL REFERENCES orgs (login),
      name TEXT NOT NULL COLLATE BINARY,
      visibility TEXT NOT NULL CHECK (visibility IN ('public', 'internal', 'private')),
      PRIMARY KEY (org, name)
    );
    CREATE TABLE branch_protections (
      org TEXT NOT NULL,
      repo TEXT NOT NULL,
      branch TEXT NOT NULL COLLATE BINARY,
      enforce_admins INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (org, repo, branch),
      FOREIGN KEY (org, repo) REFERENCES repos (org, name)
    );
    CREATE TABLE rulesets (
      org TEXT NOT NULL,
      repo TEXT NOT NULL,
      id TEXT NOT NULL COLLATE BINARY,
      branch TEXT NOT NULL COLLATE BINARY,
      bypass_role TEXT CHECK (bypass_role IN ('write', 'maintain', 'admin')),
      PRIMARY KEY (org, repo, id),
      FOREIGN KEY (org, repo) REFERENCES repos (org, name)
    );
  `);
}
