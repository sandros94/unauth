import type { DatabaseSync } from "node:sqlite";
import { type Statement, assertStatement } from "unauth/z";
import { transaction } from "../../application/db.ts";
import { placeStatement } from "../../storage/statements.ts";
import { addUser } from "../../storage/users.ts";
import { authz } from "./authz.ts";

const STATEMENTS: Statement[] = [
  { kind: "allow", subject: "ed", value: "*" },
  { kind: "allow", subject: "assistant", value: "post:read" },
  { kind: "allow", subject: "assistant", value: "post:draft" },
];

export function seed(db: DatabaseSync): void {
  transaction(db, () => {
    addUser(db, "ed");
    addUser(db, "assistant");
    for (const statement of STATEMENTS) {
      assertStatement(authz.catalog, statement);
      placeStatement(db, statement);
    }
  });
}
