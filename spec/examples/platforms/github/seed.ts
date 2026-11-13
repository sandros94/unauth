import type { DatabaseSync } from "node:sqlite";
import { type Statement, assertRole, assertStatement, placeKey } from "unauth/z";
import { transaction } from "../../application/db.ts";
import { readRoles, writeRole } from "../../storage/roles.ts";
import { placeStatement } from "../../storage/statements.ts";
import { addUser } from "../../storage/users.ts";
import { authz } from "./authz.ts";
import { addMember, enterpriseGroup, orgGroup, teamGroup } from "./groups.ts";
import { findOrg, findRepo } from "./places.ts";

const USERS = ["olivia", "ada", "mark", "nina", "tess", "rob", "carl", "lena", "erin", "vera"];

const MEMBERS: Record<string, string[]> = {
  olivia: [orgGroup("acme")],
  ada: [orgGroup("acme")],
  mark: [orgGroup("acme")],
  nina: [orgGroup("acme")],
  tess: [orgGroup("acme"), teamGroup("acme", "eng-web")],
  rob: [orgGroup("acme"), teamGroup("acme", "release")],
  lena: [orgGroup("acme-labs")],
};

const RELEASE_MANAGER = { name: "release-manager", entries: ["write", "branch-protection:bypass"] };

export function seed(db: DatabaseSync): void {
  transaction(db, () => {
    db.exec(`
      INSERT INTO enterprises (slug) VALUES ('acme-corp');
      INSERT INTO orgs (login, enterprise) VALUES ('acme', 'acme-corp'), ('acme-labs', 'acme-corp');
      INSERT INTO teams (id, org, slug, parent) VALUES
        ('team:acme:eng', 'acme', 'eng', NULL),
        ('team:acme:eng-web', 'acme', 'eng-web', 'team:acme:eng'),
        ('team:acme:release', 'acme', 'release', NULL);
      INSERT INTO repos (org, name, visibility) VALUES
        ('acme', 'api', 'private'), ('acme', 'web', 'private'),
        ('acme', 'handbook', 'internal'), ('acme', 'docs', 'public'),
        ('acme-labs', 'lab', 'private'), ('acme-labs', 'notes', 'internal');
      INSERT INTO branch_protections (org, repo, branch) VALUES ('acme', 'api', 'main');
      INSERT INTO rulesets (org, repo, id, branch) VALUES ('acme', 'web', 'main-guard', 'main');
    `);
    for (const user of USERS) addUser(db, user);
    for (const [user, groups] of Object.entries(MEMBERS)) {
      for (const group of groups) addMember(db, user, group);
    }

    const roles = readRoles(db);
    assertRole(authz.catalog, RELEASE_MANAGER, { roles });
    writeRole(db, authz, RELEASE_MANAGER, roles);

    const enterprise = placeKey({ enterprise: "acme-corp" });
    const acme = place(db, "acme");
    const api = place(db, "acme", "api");
    const statements: Statement[] = [
      assign("erin", "enterprise-owner", enterprise),
      {
        kind: "allow",
        subject: enterpriseGroup("acme-corp"),
        value: "internal-repo:read",
        place: enterprise,
      },
      assign("olivia", "owner", acme),
      assign(orgGroup("acme"), "read", acme),
      assign(teamGroup("acme", "eng"), "write", api),
      assign(teamGroup("acme", "eng-web"), "maintain", place(db, "acme", "web")),
      assign("ada", "admin", api),
      assign("carl", "read", api),
      assign("mark", RELEASE_MANAGER.name, api),
    ];
    for (const statement of statements) {
      assertStatement(authz.catalog, statement, { roles: [RELEASE_MANAGER] });
      placeStatement(db, statement);
    }
  });
}

function place(db: DatabaseSync, org: string, repo?: string): string {
  const key = repo === undefined ? findOrg(db, org)?.key : findRepo(db, org, repo)?.key;
  if (key === undefined) throw new Error(`Nothing seeded at ${org}/${repo ?? ""}.`);
  return key;
}

function assign(subject: string, role: string, at: string): Statement {
  return { kind: "assign", subject, value: role, place: at };
}
