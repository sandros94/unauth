import { type H3, HTTPError } from "h3";
import { useDB, withTransaction } from "../../../application/db.ts";
import { allowed, authorize, gate } from "../../../application/guard.ts";
import { forbidden, param, readBody, textOf } from "../../../application/http.ts";
import { requireAuthSession } from "../../../application/session.ts";
import { authz } from "../authz.ts";
import { GROUPS } from "../groups.ts";
import { repoOf } from "../places.ts";

export function repositoryRoutes(app: H3): void {
  app.get("/repos/:org/:repo", async (event) => {
    const repo = repoOf(useDB(event), event);
    const shown = { org: repo.org.login, name: repo.name, visibility: repo.visibility };
    if (repo.visibility === "public") return shown;
    const session = await requireAuthSession(event, authz);
    const permission = repo.visibility === "internal" ? "internal-repo:read" : "repo:read";
    const question = { permission, place: repo.key } as const;
    if (!allowed(event, authz, session, question, GROUPS)) throw forbidden();
    return shown;
  });

  app.put("/repos/:org/:repo/visibility", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const visibility = textOf(await readBody(event), "visibility");
    if (!["public", "internal", "private"].includes(visibility)) {
      throw new HTTPError({ status: 400, message: "No such visibility." });
    }
    withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "repo:admin", place: repo.key }, GROUPS);
      db.prepare("UPDATE repos SET visibility = ? WHERE org = ? AND name = ?").run(
        visibility,
        repo.org.login,
        repo.name,
      );
    });
    return { org: repo.org.login, name: repo.name, visibility };
  });

  app.post("/repos/:org/:repo/issues/:issue/labels", async (event) => {
    const repo = repoOf(useDB(event), event);
    await authorize(event, authz, { permission: "repo:triage", place: repo.key }, GROUPS);
    const label = textOf(await readBody(event), "label");
    event.res.status = 201;
    return { issue: Number(param(event, "issue")), labels: [label] };
  });
}
