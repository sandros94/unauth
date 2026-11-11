import type { RelatedValues } from "../../../src/z/relate.ts";
import type { Grants } from "../../../src/z/types.ts";
import type { CountedDatabase, Row } from "./database.ts";
import { text } from "./schema.ts";

/** A repository, the content of the application: `org` and `name` make its place. */
export interface Repo {
  org: string;
  name: string;
  visibility: "public" | "private";
}

/** What a request reads beside the content: a session's grants, when the id names one. */
export interface WithRepo {
  grants?: unknown;
  repo?: Repo;
}

export function putRepo(db: CountedDatabase, repo: Repo): void {
  db.write("repos.put", "INSERT INTO repos (org, name, visibility) VALUES ($org, $name, $vis)", {
    org: repo.org,
    name: repo.name,
    vis: repo.visibility,
  });
}

export function readRepo(db: CountedDatabase, org: string, name: string): Repo | undefined {
  const [row] = db.read("repo", "SELECT visibility FROM repos WHERE org = $org AND name = $name", {
    org,
    name,
  });
  return row === undefined ? undefined : repoOf(org, name, row.visibility);
}

/** Lists `subject` in exactly `groups`. */
export function putMemberships(
  db: CountedDatabase,
  subject: string,
  groups: readonly string[],
): void {
  db.write("memberships.clear", "DELETE FROM memberships WHERE subject = $subject", { subject });
  for (const grp of groups) {
    db.write("memberships.put", "INSERT INTO memberships (subject, grp) VALUES ($subject, $grp)", {
      subject,
      grp,
    });
  }
}

/** A team whose members count for `parent` too. */
export function putTeam(db: CountedDatabase, id: string, parent?: string): void {
  db.write("teams.put", "INSERT INTO teams (id, parent) VALUES ($id, $parent)", {
    id,
    parent: parent ?? null,
  });
}

/** Keeps grants as one value. */
export function saveSession(
  db: CountedDatabase,
  id: string,
  subject: string,
  grants: Grants,
): void {
  db.write("sessions.save", "INSERT INTO sessions (id, subject, grants) VALUES ($id, $s, $g)", {
    id,
    s: subject,
    g: JSON.stringify(grants),
  });
}

/** Keeps grants one entry per row, the tables in a head row beside them. */
export function saveSessionRows(
  db: CountedDatabase,
  id: string,
  subject: string,
  grants: Grants,
): void {
  const { nt, ...head } = grants;
  db.write("sessions.head", "INSERT INTO session_heads (id, subject, head) VALUES ($id, $s, $h)", {
    id,
    s: subject,
    h: JSON.stringify(head),
  });
  for (const [name, entry] of Object.entries(nt)) {
    db.write(
      "sessions.entry",
      "INSERT INTO session_entries (session, name, entry) VALUES ($id, $name, $entry)",
      { id, name, entry: JSON.stringify(entry) },
    );
  }
}

/** The session kept as one value and the repository, in one read. */
export function sessionWithRepo(
  db: CountedDatabase,
  id: string,
  repo: Omit<Repo, "visibility">,
): WithRepo {
  const rows = db.read(
    "session+repo",
    `SELECT 'session' AS row, grants AS a FROM sessions WHERE id = $id
     UNION ALL
     SELECT 'repo', visibility FROM repos WHERE org = $org AND name = $name`,
    { id, org: repo.org, name: repo.name },
  );
  return withRepo(repo, rows, (row) => JSON.parse(text(row, "a")));
}

/**
 * The session kept one entry per row and the repository, in one read. With `related`, only the
 * entries it names and every entry of a stored role are read, with the head that holds the tables
 * they index.
 */
export function sessionRowsWithRepo(
  db: CountedDatabase,
  id: string,
  repo: Omit<Repo, "visibility">,
  related?: RelatedValues,
): WithRepo {
  const names =
    related === undefined
      ? null
      : JSON.stringify([...related.allow, ...related.deny, ...related.exclude, ...related.presets]);
  const rows = db.read(
    related === undefined ? "session-rows+repo" : "session-related+repo",
    `SELECT 'session' AS row, head AS a, NULL AS b FROM session_heads WHERE id = $id
     UNION ALL
     SELECT 'entry', name, entry FROM session_entries
     WHERE session = $id
       AND ($names IS NULL OR name IN (SELECT value FROM json_each($names)) OR substr(name, 1, 1) = '#')
     UNION ALL
     SELECT 'repo', visibility, NULL FROM repos WHERE org = $org AND name = $name`,
    { id, org: repo.org, name: repo.name, names },
  );
  const nt: Record<string, unknown> = {};
  for (const row of rows) {
    if (row.row === "entry") nt[text(row, "a")] = JSON.parse(text(row, "b"));
  }
  return withRepo(repo, rows, (row) => {
    const head: unknown = JSON.parse(text(row, "a"));
    return typeof head === "object" && head !== null ? { ...head, nt } : head;
  });
}

function withRepo(
  repo: Omit<Repo, "visibility">,
  rows: readonly Row[],
  grantsOf: (row: Row) => unknown,
): WithRepo {
  const session = rows.find((row) => row.row === "session");
  const found = rows.find((row) => row.row === "repo");
  return {
    ...(session !== undefined && { grants: grantsOf(session) }),
    ...(found !== undefined && { repo: repoOf(repo.org, repo.name, found.a) }),
  };
}

function repoOf(org: string, name: string, visibility: unknown): Repo {
  return { org, name, visibility: visibility === "public" ? "public" : "private" };
}
