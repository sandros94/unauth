import type { DatabaseSync } from "node:sqlite";
import { type H3Event, HTTPError } from "h3";
import { placeKey } from "unauth/z";
import { type Row, integer, text } from "../../storage/rows.ts";
import { type RepositoryRole, isRepositoryRole } from "./authz.ts";

export type Visibility = "public" | "internal" | "private";

export interface Org {
  login: string;
  key: string;
  outsideCollaborators: "admins" | "owners";
}

export interface Repo {
  org: Org;
  name: string;
  key: string;
  visibility: Visibility;
}

export interface Ruleset {
  id: string;
  key: string;
  bypassRole: RepositoryRole | undefined;
}

export function findOrg(db: DatabaseSync, login: string): Org | undefined {
  const row = db
    .prepare("SELECT login, enterprise, outside_collaborators FROM orgs WHERE login = ?")
    .get(login);
  return row === undefined ? undefined : orgOf(row);
}

export function findRepo(db: DatabaseSync, org: string, name: string): Repo | undefined {
  const row = db
    .prepare(
      `SELECT orgs.login, orgs.enterprise, orgs.outside_collaborators, repos.name, repos.visibility
       FROM repos JOIN orgs ON orgs.login = repos.org WHERE repos.org = ? AND repos.name = ?`,
    )
    .get(org, name);
  if (row === undefined) return undefined;
  const owner = orgOf(row);
  return {
    org: owner,
    name: text(row, "name"),
    key: placeKey({ repo: text(row, "name") }, { under: owner.key }),
    visibility: visibilityOf(text(row, "visibility")),
  };
}

export function repoOf(db: DatabaseSync, event: H3Event): Repo {
  const { org, repo } = event.context.params ?? {};
  const found = org === undefined || repo === undefined ? undefined : findRepo(db, org, repo);
  if (found === undefined) throw new HTTPError({ status: 404, message: "No such repository." });
  return found;
}

export function findTeam(db: DatabaseSync, org: string, slug: string): string | undefined {
  const row = db.prepare("SELECT id FROM teams WHERE org = ? AND slug = ?").get(org, slug);
  return row === undefined ? undefined : text(row, "id");
}

export function protectionOf(
  db: DatabaseSync,
  repo: Repo,
  branch: string,
): { enforceAdmins: boolean } | undefined {
  const row = db
    .prepare(
      "SELECT enforce_admins FROM branch_protections WHERE org = ? AND repo = ? AND branch = ?",
    )
    .get(repo.org.login, repo.name, branch);
  return row === undefined ? undefined : { enforceAdmins: integer(row, "enforce_admins") === 1 };
}

export function rulesetsOf(db: DatabaseSync, repo: Repo, branch: string): Ruleset[] {
  return db
    .prepare("SELECT id, bypass_role FROM rulesets WHERE org = ? AND repo = ? AND branch = ?")
    .all(repo.org.login, repo.name, branch)
    .map((row) => rulesetOf(repo, row));
}

export function findRuleset(db: DatabaseSync, repo: Repo, id: string): Ruleset | undefined {
  const row = db
    .prepare("SELECT id, bypass_role FROM rulesets WHERE org = ? AND repo = ? AND id = ?")
    .get(repo.org.login, repo.name, id);
  return row === undefined ? undefined : rulesetOf(repo, row);
}

function rulesetOf(repo: Repo, row: Row): Ruleset {
  const role = row.bypass_role;
  return {
    id: text(row, "id"),
    key: placeKey({ ruleset: text(row, "id") }, { under: repo.key }),
    bypassRole: isRepositoryRole(role) ? role : undefined,
  };
}

function orgOf(row: Row): Org {
  const login = text(row, "login");
  const enterprise = row.enterprise;
  return {
    login,
    key:
      typeof enterprise === "string"
        ? placeKey({ enterprise, org: login })
        : placeKey({ org: login }),
    outsideCollaborators: text(row, "outside_collaborators") === "owners" ? "owners" : "admins",
  };
}

function visibilityOf(value: string): Visibility {
  if (value === "public" || value === "internal") return value;
  return "private";
}
