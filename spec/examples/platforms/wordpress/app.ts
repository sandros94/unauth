import { DatabaseSync } from "node:sqlite";
import type { H3 } from "h3";
import { createApp } from "../../application/app.ts";
import { startSession } from "../../application/session.ts";
import { standInUser } from "../../application/sign-in.ts";
import { createTables } from "../../storage/schema.ts";
import { postRoutes } from "./routes/posts.ts";
import { userRoutes } from "./routes/users.ts";
import { createWordPressTables } from "./tables.ts";

export interface WordPress {
  app: H3;
  db: DatabaseSync;
}

export function createWordPress(): WordPress {
  const db = new DatabaseSync(":memory:");
  createTables(db);
  createWordPressTables(db);
  const app = createApp(db);
  app.post("/session", async (event) => {
    const subject = await standInUser(event);
    await startSession(event, { subject });
    return { subject };
  });
  postRoutes(app);
  userRoutes(app);
  return { app, db };
}
