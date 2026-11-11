import type { RelatedValues } from "../../../src/z/relate.ts";
import type { Statement, StoredRole } from "../../../src/z/types.ts";
import type { CountedDatabase, Row } from "./database.ts";
import { ON_CHAIN, UNDER, placeParams } from "./places.ts";
import { roleOf, statementOf, text } from "./schema.ts";

export interface GatherQuery {
  subject: string;
  /** The time of the call, in seconds: statements ended by then are left out. */
  at: number;
  /** Keys whose chains are read. */
  chain: readonly string[];
  /** Keys whose subtrees are read. */
  under: readonly string[];
  /** Stored roles to read beside the ones the statements assign. */
  roles?: readonly string[];
  /** Whether to read the root's permanent allows of `*`, about anyone. */
  managers?: boolean;
  /** Only the statements carrying these values, with every assignment of a stored role. */
  related?: RelatedValues;
}

export interface Gathered {
  groups: string[];
  statements: Statement[];
  roles: StoredRole[];
  managers: Statement[];
}

const GATHER = `
  WITH RECURSIVE
    groups(grp) AS (
      SELECT grp FROM memberships WHERE subject = $subject
      UNION
      SELECT teams.parent FROM teams JOIN groups ON teams.id = groups.grp
      WHERE teams.parent IS NOT NULL
    ),
    found AS (
      SELECT kind, subject, value, place, expires_at FROM statements
      WHERE (subject = $subject OR subject IN (SELECT grp FROM groups))
        AND (expires_at IS NULL OR expires_at > $at)
        AND (${ON_CHAIN} OR ${UNDER})
        AND (
          $related IS NULL
          OR (kind = 'allow' AND value IN (SELECT value FROM json_each($related, '$.allow')))
          OR (kind = 'deny' AND value IN (SELECT value FROM json_each($related, '$.deny')))
          OR (kind = 'exclude' AND value IN (SELECT value FROM json_each($related, '$.exclude')))
          OR (kind = 'assign' AND (
            value IN (SELECT value FROM json_each($related, '$.presets'))
            OR value IN (SELECT name FROM roles)
          ))
        )
    ),
    named(name) AS (
      SELECT value FROM found WHERE kind = 'assign'
      UNION
      SELECT value FROM json_each($roles)
      UNION
      SELECT CASE WHEN substr(entry.value, 1, 1) = '-' THEN substr(entry.value, 2) ELSE entry.value END
      FROM roles JOIN named ON roles.name = named.name, json_each(roles.entries) AS entry
    )
  SELECT 'group' AS row, grp AS kind, NULL AS subject, NULL AS value, NULL AS place, NULL AS expires_at
  FROM groups
  UNION ALL
  SELECT 'statement', kind, subject, value, place, expires_at FROM found
  UNION ALL
  SELECT 'role', name, home, entries, NULL, NULL FROM roles WHERE name IN (SELECT name FROM named)
  UNION ALL
  SELECT 'manager', kind, subject, value, place, expires_at FROM statements
  WHERE $managers = 1 AND kind = 'allow' AND value = '*' AND place = '/' AND expires_at IS NULL`;

/**
 * Everything a call of the engine needs about a subject, in one read: its groups, a team counting
 * for the teams above it, the live statements about the subject and those groups on the chains
 * and under the keys asked, the stored roles they assign with the roles those reference, and the
 * root's permanent allows of `*` when asked.
 */
export function gather(db: CountedDatabase, label: string, query: GatherQuery): Gathered {
  const rows = db.read(label, GATHER, {
    subject: query.subject,
    at: query.at,
    ...placeParams(query.chain, query.under),
    roles: JSON.stringify(query.roles ?? []),
    managers: query.managers === true ? 1 : 0,
    related: query.related === undefined ? null : JSON.stringify(query.related),
  });
  return {
    groups: of(rows, "group").map((row) => text(row, "kind")),
    statements: of(rows, "statement").map(statementOf),
    roles: of(rows, "role").map((row) =>
      roleOf({ name: row.kind ?? null, home: row.subject ?? null, entries: row.value ?? null }),
    ),
    managers: of(rows, "manager").map(statementOf),
  };
}

function of(rows: readonly Row[], kind: string): Row[] {
  return rows.filter((row) => row.row === kind);
}
