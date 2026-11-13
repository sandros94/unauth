import { type H3, type H3Event, HTTPError } from "h3";
import type { Statement } from "unauth/z";
import { statementIssues } from "../../../application/changes.ts";
import { useDB, withTransaction } from "../../../application/db.ts";
import { allowed, gate } from "../../../application/guard.ts";
import { flagOf, invalid, param, readBody, textOf } from "../../../application/http.ts";
import { type SignedIn, requireAuthSession } from "../../../application/session.ts";
import { placeStatement } from "../../../storage/statements.ts";
import { type Permission, authz, isRepositoryRole } from "../authz.ts";
import { GROUPS } from "../groups.ts";
import { type Repo, findRuleset, findTeam, protectionOf, repoOf, rulesetsOf } from "../places.ts";

export function rulesRoutes(app: H3): void {
  app.post("/repos/:org/:repo/pushes", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const branch = textOf(await readBody(event), "branch");
    const refusal = pushRefusal(event, session, { repo, branch });
    if (refusal !== undefined) throw new HTTPError({ status: 403, message: refusal });
    event.res.status = 201;
    return { branch };
  });

  app.put("/repos/:org/:repo/branches/:branch/protection", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const branch = param(event, "branch");
    const enforceAdmins = flagOf(await readBody(event), "enforceAdmins");
    withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "rules:manage", place: repo.key }, GROUPS);
      db.prepare(
        `INSERT INTO branch_protections (org, repo, branch, enforce_admins) VALUES (?, ?, ?, ?)
         ON CONFLICT (org, repo, branch) DO UPDATE SET enforce_admins = excluded.enforce_admins`,
      ).run(repo.org.login, repo.name, branch, enforceAdmins ? 1 : 0);
    });
    return { branch, enforceAdmins };
  });

  app.put("/repos/:org/:repo/rulesets/:ruleset/bypass-role", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const ruleset = param(event, "ruleset");
    const role = textOf(await readBody(event), "role");
    if (!isRepositoryRole(role)) throw new HTTPError({ status: 400, message: "No such role." });
    withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "rules:manage", place: repo.key }, GROUPS);
      db.prepare("UPDATE rulesets SET bypass_role = ? WHERE org = ? AND repo = ? AND id = ?").run(
        role,
        repo.org.login,
        repo.name,
        ruleset,
      );
    });
    return { ruleset, role };
  });

  app.put("/repos/:org/:repo/rulesets/:ruleset/bypass-teams/:team", async (event) => {
    const repo = repoOf(useDB(event), event);
    const session = await requireAuthSession(event, authz);
    const placed = withTransaction(event, (db) => {
      gate(db, authz, session, { permission: "rules:manage", place: repo.key }, GROUPS);
      const ruleset = findRuleset(db, repo, param(event, "ruleset"));
      const team = findTeam(db, repo.org.login, param(event, "team"));
      if (ruleset === undefined || team === undefined) {
        throw new HTTPError({ status: 404, message: "No such ruleset or team." });
      }
      const statement: Statement = {
        kind: "assign",
        subject: team,
        value: "ruleset-bypass",
        place: ruleset.key,
      };
      const issues = statementIssues(db, authz, [statement]);
      if (issues.length > 0) throw invalid(issues);
      placeStatement(db, statement);
      return statement;
    });
    return { ruleset: param(event, "ruleset"), team: placed.subject };
  });
}

function pushRefusal(
  event: H3Event,
  session: SignedIn,
  target: { repo: Repo; branch: string },
): string | undefined {
  const { repo, branch } = target;
  const db = useDB(event);
  const can = (permission: Permission, place = repo.key): boolean =>
    allowed(event, authz, session, { permission, place }, GROUPS);
  if (!can("repo:write")) return "Not allowed.";
  const protection = protectionOf(db, repo, branch);
  if (protection?.enforceAdmins === true) return "The branch is protected.";
  if (protection !== undefined && !can("branch-protection:bypass")) {
    return "The branch is protected.";
  }
  for (const ruleset of rulesetsOf(db, repo, branch)) {
    const byRole = ruleset.bypassRole !== undefined && can(`repo:${ruleset.bypassRole}`);
    if (!byRole && !can("ruleset:bypass", ruleset.key)) {
      return `Ruleset ${ruleset.id} blocks the push.`;
    }
  }
  return undefined;
}
