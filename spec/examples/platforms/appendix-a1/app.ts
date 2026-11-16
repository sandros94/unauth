import { DatabaseSync } from "node:sqlite";
import type { H3 } from "h3";
import type { Statement } from "unauth/z";
import { createApp } from "../../application/app.ts";
import { statementIssues } from "../../application/changes.ts";
import { withTransaction } from "../../application/db.ts";
import { authorize, gate } from "../../application/guard.ts";
import { invalid, param, readBody, textOf } from "../../application/http.ts";
import { type GrantsOf, requireAuthSession, startSession } from "../../application/session.ts";
import { grantsFor, standInUser } from "../../application/sign-in.ts";
import { createTables } from "../../storage/schema.ts";
import { placeStatement } from "../../storage/statements.ts";
import { authz } from "./authz.ts";

export interface AppendixA1 {
  app: H3;
  db: DatabaseSync;
}

export function createAppendixA1(): AppendixA1 {
  const db = new DatabaseSync(":memory:");
  createTables(db);
  const grantsOf: GrantsOf = (subject, bases) => grantsFor(db, authz, { subject }, { bases });
  const app = createApp(db, grantsOf);

  app.post("/session", async (event) => {
    const subject = await standInUser(event);
    await startSession(event, { subject, grants: grantsOf(subject) });
    return { subject };
  });

  app.get("/posts/:id", async (event) => {
    await authorize(event, authz, { permission: "post:read" });
    return { id: param(event, "id") };
  });

  app.post("/posts", async (event) => {
    await authorize(event, authz, { permission: "post:draft" });
    event.res.status = 201;
    return { status: "draft" };
  });

  app.post("/posts/:id/publish", async (event) => {
    await authorize(event, authz, { permission: "post:publish" });
    return { id: param(event, "id"), status: "publish" };
  });

  app.post("/allows", async (event) => {
    const session = await requireAuthSession(event, authz);
    const body = await readBody(event);
    const statement: Statement = {
      kind: "allow",
      subject: textOf(body, "subject"),
      value: textOf(body, "permission"),
    };
    withTransaction(event, (tx) => {
      gate(tx, authz, session, { permission: "access:manage" });
      const issues = statementIssues(tx, authz, [statement]);
      if (issues.length > 0) throw invalid(issues);
      placeStatement(tx, statement);
    });
    return { subject: statement.subject, permission: statement.value };
  });

  return { app, db };
}
