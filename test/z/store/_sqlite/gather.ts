import type { RelatedValues } from "../../../../src/z/relate.ts";
import type { Statement, StoredRole, SubjectStatements } from "../../../../src/z/types.ts";
import type { CountedDatabase, Row } from "./database.ts";
import { ON_CHAIN, UNDER, placeParams } from "./places.ts";
import { roleOf, statementOf } from "./schema.ts";

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
  /** Only the statements carrying these values, with every assignment of a stored role. */
  related?: RelatedValues;
}

/** What the engine is handed: the statements that apply to the subject, with the roles they assign. */
export interface Gathered extends SubjectStatements {
  statements: Statement[];
  roles: StoredRole[];
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
  SELECT 'statement' AS row, kind, subject, value, place, expires_at FROM found
  UNION ALL
  SELECT 'role', name, entries, NULL, NULL, NULL FROM roles WHERE name IN (SELECT name FROM named)`;

/**
 * Everything a call of the engine needs about a subject, in one read: the live statements about
 * the subject and about its groups, joined on its memberships, a team counting for the teams above
 * it, on the chains and under the keys asked, and the stored roles they assign or the call names,
 * with the roles those reference.
 */
export function gather(db: CountedDatabase, label: string, query: GatherQuery): Gathered {
  const rows = db.read(label, GATHER, {
    subject: query.subject,
    at: query.at,
    ...placeParams(query.chain, query.under),
    roles: JSON.stringify(query.roles ?? []),
    related: query.related === undefined ? null : JSON.stringify(query.related),
  });
  return {
    subject: query.subject,
    statements: of(rows, "statement").map(statementOf),
    roles: of(rows, "role").map((row) =>
      roleOf({ name: row.kind ?? null, entries: row.subject ?? null }),
    ),
  };
}

function of(rows: readonly Row[], kind: string): Row[] {
  return rows.filter((row) => row.row === kind);
}
