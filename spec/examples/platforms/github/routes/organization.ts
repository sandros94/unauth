import type { DatabaseSync } from "node:sqlite";
import { type H3, type H3Event, HTTPError } from "h3";
import type { Statement } from "unauth/z";
import { statementIssues } from "../../../application/changes.ts";
import { useDB, withTransaction } from "../../../application/db.ts";
import { gate } from "../../../application/guard.ts";
import { invalid, param, readBody, textOf } from "../../../application/http.ts";
import { requireAuthSession } from "../../../application/session.ts";
import { clearAssignments, placeStatement } from "../../../storage/statements.ts";
import { authz } from "../authz.ts";
import { GROUPS, addMember, isMember, orgGroup } from "../groups.ts";
import { type Org, findOrg, findTeam } from "../places.ts";

const BASE_PERMISSIONS = ["none", "read", "write", "admin"];

export function organizationRoutes(app: H3): void {
  app.put("/orgs/:org/base-permission", async (event) => {
    const org = orgOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const permission = textOf(await readBody(event), "permission");
    if (!BASE_PERMISSIONS.includes(permission)) {
      throw new HTTPError({ status: 400, message: "No such base permission." });
    }
    withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "access:manage", place: org.key }, GROUPS);
      const members = { subject: orgGroup(org.login), place: org.key };
      const statements: Statement[] =
        permission === "none" ? [] : [{ kind: "assign", ...members, value: permission }];
      const issues = statementIssues(db, authz, statements);
      if (issues.length > 0) throw invalid(issues);
      clearAssignments(db, members);
      for (const statement of statements) placeStatement(db, statement);
    });
    return { org: org.login, permission };
  });

  app.put("/orgs/:org/outside-collaborators", async (event) => {
    const org = orgOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const policy = textOf(await readBody(event), "policy");
    if (policy !== "admins" && policy !== "owners") {
      throw new HTTPError({ status: 400, message: "No such policy." });
    }
    withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "member:manage", place: org.key }, GROUPS);
      db.prepare("UPDATE orgs SET outside_collaborators = ? WHERE login = ?").run(
        policy,
        org.login,
      );
    });
    return { org: org.login, policy };
  });

  app.put("/orgs/:org/teams/:team/members/:user", async (event) => {
    const org = orgOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const user = param(event, "user");
    const team = withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "member:manage", place: org.key }, GROUPS);
      const found = findTeam(db, org.login, param(event, "team"));
      if (found === undefined) throw new HTTPError({ status: 404, message: "No such team." });
      if (!isMember(db, user, orgGroup(org.login))) {
        throw new HTTPError({
          status: 422,
          message: "Only members of the organization join a team.",
        });
      }
      addMember(db, user, found);
      return found;
    });
    return { team, user };
  });
}

function orgOf(db: DatabaseSync, event: H3Event): Org {
  const org = findOrg(db, param(event, "org"));
  if (org === undefined) throw new HTTPError({ status: 404, message: "No such organization." });
  return org;
}
