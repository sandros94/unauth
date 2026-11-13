import { type H3, HTTPError } from "h3";
import type { Statement } from "unauth/z";
import { statementIssues } from "../../../application/changes.ts";
import { withTransaction } from "../../../application/db.ts";
import { gate } from "../../../application/guard.ts";
import { forbidden, invalid, param, readBody, textOf } from "../../../application/http.ts";
import { requireAuthSession } from "../../../application/session.ts";
import { readRoles } from "../../../storage/roles.ts";
import { clearAssignments, placeStatement } from "../../../storage/statements.ts";
import { addUser, userExists } from "../../../storage/users.ts";
import { CAPABILITIES as cap, authz } from "../authz.ts";
import { defaultRole } from "../tables.ts";

export function userRoutes(app: H3): void {
  app.post("/users", async (event) => {
    const session = await requireAuthSession(event, authz);
    const user = textOf(await readBody(event), "user");
    const role = withTransaction(event, (db) => {
      gate(db, authz, session, { permission: cap.create_users });
      if (userExists(db, user)) throw new HTTPError({ status: 409, message: "The user exists." });
      const statement: Statement = { kind: "assign", subject: user, value: defaultRole(db) };
      const issues = statementIssues(db, authz, [statement]);
      if (issues.length > 0) throw invalid(issues);
      addUser(db, user);
      placeStatement(db, statement);
      return statement.value;
    });
    event.res.status = 201;
    return { user, role };
  });

  app.put("/users/:user/role", async (event) => {
    const session = await requireAuthSession(event, authz);
    const user = param(event, "user");
    const role = textOf(await readBody(event), "role");
    withTransaction(event, (db) => {
      gate(db, authz, session, { permission: cap.promote_users });
      if (!userExists(db, user)) throw new HTTPError({ status: 404, message: "No such user." });
      const roles = readRoles(db);
      const statement: Statement = { kind: "assign", subject: user, value: role };
      const issues = authz.validateStatement(statement, { roles });
      if (issues.length > 0) {
        throw invalid(issues, "Sorry, you are not allowed to give users that role.");
      }
      if (
        user === session.subject &&
        !authz.resolveRole(role, { roles }).includes(cap.promote_users)
      ) {
        throw forbidden("Sorry, you cannot remove your own role.");
      }
      clearAssignments(db, { subject: user });
      placeStatement(db, statement);
    });
    return { user, role };
  });
}
