import { DatabaseSync } from "node:sqlite";
import type { H3 } from "h3";
import { createApp } from "../../application/app.ts";
import { type GrantsOf, startSession } from "../../application/session.ts";
import { grantsFor, standInUser } from "../../application/sign-in.ts";
import { createTables } from "../../storage/schema.ts";
import { authz } from "./authz.ts";
import { GROUPS } from "./groups.ts";
import { accessRoutes } from "./routes/access.ts";
import { organizationRoutes } from "./routes/organization.ts";
import { repositoryRoutes } from "./routes/repository.ts";
import { rulesRoutes } from "./routes/rules.ts";
import { createGitHubTables } from "./tables.ts";

export interface GitHub {
  app: H3;
  db: DatabaseSync;
}

export function createGitHub(): GitHub {
  const db = new DatabaseSync(":memory:");
  createTables(db);
  createGitHubTables(db);
  const grantsOf: GrantsOf = (subject, bases) =>
    grantsFor(db, authz, { subject, ...GROUPS }, { bases });
  const app = createApp(db, grantsOf);
  app.post("/session", async (event) => {
    const subject = await standInUser(event);
    await startSession(event, { subject, grants: grantsOf(subject) });
    return { subject };
  });
  repositoryRoutes(app);
  accessRoutes(app);
  organizationRoutes(app);
  rulesRoutes(app);
  return { app, db };
}
