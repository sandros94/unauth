import { type H3, HTTPError } from "h3";
import type { Statement } from "unauth/z";
import { statementIssues } from "../../../application/changes.ts";
import { useDB, withTransaction } from "../../../application/db.ts";
import { gate } from "../../../application/guard.ts";
import { invalid, param, readBody, textOf } from "../../../application/http.ts";
import { requireAuthSession } from "../../../application/session.ts";
import { clearAssignments, placeStatement } from "../../../storage/statements.ts";
import { userExists } from "../../../storage/users.ts";
import { authz } from "../authz.ts";
import { GROUPS, isMember, orgGroup } from "../groups.ts";
import { findTeam, repoOf } from "../places.ts";

export function accessRoutes(app: H3): void {
  app.put("/repos/:org/:repo/collaborators/:user", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const user = param(event, "user");
    const role = textOf(await readBody(event), "role");
    const outside = withTransaction(event, (db) => {
      if (!userExists(db, user)) throw new HTTPError({ status: 404, message: "No such user." });
      const notMember = !isMember(db, user, orgGroup(repo.org.login));
      const ownersOnly = notMember && repo.org.outsideCollaborators === "owners";
      gate(
        db,
        authz,
        session,
        ownersOnly
          ? { permission: "member:manage", place: repo.org.key }
          : { permission: "access:manage", place: repo.key },
        GROUPS,
      );
      const statement: Statement = { kind: "assign", subject: user, value: role, place: repo.key };
      const issues = statementIssues(db, authz, [statement]);
      if (issues.length > 0) throw invalid(issues);
      clearAssignments(db, statement);
      placeStatement(db, statement);
      return notMember;
    });
    return { user, role, outside };
  });

  app.delete("/repos/:org/:repo/collaborators/:user", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const user = param(event, "user");
    withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "access:manage", place: repo.key }, GROUPS);
      clearAssignments(db, { subject: user, place: repo.key });
    });
    return { user };
  });

  app.put("/repos/:org/:repo/teams/:team", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const role = textOf(await readBody(event), "role");
    const team = withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "access:manage", place: repo.key }, GROUPS);
      const found = findTeam(db, repo.org.login, param(event, "team"));
      if (found === undefined) throw new HTTPError({ status: 404, message: "No such team." });
      const statement: Statement = { kind: "assign", subject: found, value: role, place: repo.key };
      const issues = statementIssues(db, authz, [statement]);
      if (issues.length > 0) throw invalid(issues);
      clearAssignments(db, statement);
      placeStatement(db, statement);
      return found;
    });
    return { team, role };
  });
}
