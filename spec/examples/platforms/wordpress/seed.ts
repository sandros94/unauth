import type { DatabaseSync } from "node:sqlite";
import { type Statement, assertStatement } from "unauth/z";
import { transaction } from "../../application/db.ts";
import { readRoles } from "../../storage/roles.ts";
import { placeStatement } from "../../storage/statements.ts";
import { addUser } from "../../storage/users.ts";
import { CAPABILITIES as cap, authz } from "./authz.ts";
import { populateRoles } from "./roles.ts";

const ROLES: Record<string, string> = {
  adele: "administrator",
  edgar: "editor",
  elena: "editor",
  arthur: "author",
  otto: "author",
  dora: "author",
  connie: "contributor",
  cora: "contributor",
  sam: "subscriber",
};

const STATEMENTS: Statement[] = [
  ...Object.entries(ROLES).map(([subject, role]): Statement => ({
    kind: "assign",
    subject,
    value: role,
  })),
  { kind: "exclude", subject: "dora", value: cap.publish_posts },
  { kind: "allow", subject: "cora", value: cap.publish_posts },
  { kind: "allow", subject: "elena", value: cap.promote_users },
];

export function seed(db: DatabaseSync): void {
  populateRoles(db);
  transaction(db, () => {
    for (const user of Object.keys(ROLES)) addUser(db, user);
    db.exec(`
      INSERT INTO posts (id, author, status, title) VALUES
        (1, 'arthur', 'publish', 'Hello world'),
        (2, 'arthur', 'draft', 'Arthur''s draft'),
        (3, 'arthur', 'private', 'Arthur''s notes'),
        (4, 'otto', 'draft', 'Otto''s draft'),
        (5, 'otto', 'publish', 'Otto''s story'),
        (6, 'connie', 'pending', 'Connie''s pitch'),
        (7, 'otto', 'private', 'Otto''s notes'),
        (8, 'dora', 'draft', 'Dora''s draft'),
        (9, 'cora', 'draft', 'Cora''s draft'),
        (10, 'dora', 'publish', 'Dora''s story');
    `);
    const roles = readRoles(db);
    for (const statement of STATEMENTS) {
      assertStatement(authz.catalog, statement, { roles });
      placeStatement(db, statement);
    }
  });
}
