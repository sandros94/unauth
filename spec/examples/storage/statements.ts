import type { DatabaseSync } from "node:sqlite";
import type { Authz, Question, Statement, SubjectStatements } from "unauth/z";
import { placeChain, placeRange } from "unauth/z";
import { presetsOf } from "./roles.ts";
import { type Row, roleOf, statementOf } from "./rows.ts";

export interface Asker {
  subject: string;
  identifiers?: string;
}

export function identifiersOf(asker: Asker): string {
  return `identifiers(id) AS (${asker.identifiers ?? "SELECT $subject"})`;
}

export function readForQuestion(
  db: DatabaseSync,
  authz: Authz,
  asker: Asker,
  question: Question,
  at: number,
): SubjectStatements {
  return read(db, asker, at, {
    where: `place IN (SELECT value FROM json_each($chain)) AND (
      (kind = 'deny' AND value IN (SELECT value FROM json_each($related, '$.deny')))
      OR (kind = 'exclude' AND value IN (SELECT value FROM json_each($related, '$.exclude')))
      OR (kind = 'allow' AND value IN (SELECT value FROM json_each($related, '$.allow')))
      OR (kind = 'assign' AND (
        value IN (SELECT value FROM json_each($related, '$.presets'))
        OR value NOT IN (SELECT value FROM json_each($presets))
      ))
    )`,
    params: {
      chain: JSON.stringify(placeChain(question.place ?? "/")),
      related: JSON.stringify(authz.relatedValues(question.permission)),
      presets: JSON.stringify(presetsOf(authz)),
    },
  });
}

export function readForGrants(
  db: DatabaseSync,
  asker: Asker,
  options: { bases: readonly string[]; at: number },
): SubjectStatements {
  const ranges = options.bases.map((base) => {
    const { after, before } = placeRange(base);
    return [after, before];
  });
  return read(db, asker, options.at, {
    where: `place IN (SELECT value FROM json_each($chain)) OR EXISTS (
      SELECT 1 FROM json_each($ranges) AS range
      WHERE place > range.value ->> '$[0]' AND place < range.value ->> '$[1]'
    )`,
    params: {
      chain: JSON.stringify([...new Set(options.bases.flatMap((base) => placeChain(base)))]),
      ranges: JSON.stringify(ranges),
    },
  });
}

export function placeStatement(db: DatabaseSync, statement: Statement): void {
  const { kind, subject, value, place = "/", expiresAt } = statement;
  db.prepare(
    `INSERT INTO statements (kind, subject, value, place, expires_at) VALUES (?, ?, ?, ?, ?)
     ON CONFLICT (kind, subject, value, place) DO UPDATE SET expires_at = excluded.expires_at`,
  ).run(kind, subject, value, place, expiresAt ?? null);
}

export function clearAssignments(
  db: DatabaseSync,
  target: { subject: string; place?: string },
): void {
  db.prepare("DELETE FROM statements WHERE kind = 'assign' AND subject = ? AND place = ?").run(
    target.subject,
    target.place ?? "/",
  );
}

function read(
  db: DatabaseSync,
  asker: Asker,
  at: number,
  query: { where: string; params: Record<string, string> },
): SubjectStatements {
  const rows = db
    .prepare(
      `WITH RECURSIVE ${identifiersOf(asker)},
       found AS (
         SELECT kind, subject, value, place, expires_at FROM statements
         WHERE subject IN (SELECT id FROM identifiers)
           AND (expires_at IS NULL OR expires_at > $at)
           AND (${query.where})
       ),
       named(name) AS (
         SELECT value FROM found WHERE kind = 'assign'
         UNION
         SELECT CASE WHEN substr(entry.value, 1, 1) = '-' THEN substr(entry.value, 2) ELSE entry.value END
         FROM roles JOIN named ON roles.name = named.name, json_each(roles.entries) AS entry
       )
       SELECT kind, subject, value, place, expires_at, NULL AS entries FROM found
       UNION ALL
       SELECT NULL, NULL, name, NULL, NULL, entries FROM roles WHERE name IN (SELECT name FROM named)`,
    )
    .all({ subject: asker.subject, at, ...query.params });
  return {
    subject: asker.subject,
    statements: rows.filter(isStatementRow).map(statementOf),
    roles: rows.filter((row) => !isStatementRow(row)).map((row) => roleOf(row, "value")),
  };
}

function isStatementRow(row: Row): boolean {
  return row.kind !== null;
}
