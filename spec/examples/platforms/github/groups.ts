import type { DatabaseSync } from "node:sqlite";

export const GROUPS = {
  identifiers: `
  SELECT $subject
  UNION SELECT grp FROM memberships WHERE member = $subject
  UNION SELECT teams.parent FROM teams JOIN identifiers ON teams.id = identifiers.id
  WHERE teams.parent IS NOT NULL
  UNION SELECT 'enterprise:' || orgs.enterprise FROM orgs JOIN identifiers
  ON identifiers.id = 'org:' || orgs.login WHERE orgs.enterprise IS NOT NULL
`,
};

export function addMember(db: DatabaseSync, member: string, group: string): void {
  db.prepare("INSERT OR IGNORE INTO memberships (member, grp) VALUES (?, ?)").run(member, group);
}

export function isMember(db: DatabaseSync, member: string, group: string): boolean {
  return (
    db.prepare("SELECT 1 FROM memberships WHERE member = ? AND grp = ?").get(member, group) !==
    undefined
  );
}

export function orgGroup(org: string): string {
  return `org:${org}`;
}

export function teamGroup(org: string, team: string): string {
  return `team:${org}:${team}`;
}

export function enterpriseGroup(enterprise: string): string {
  return `enterprise:${enterprise}`;
}
