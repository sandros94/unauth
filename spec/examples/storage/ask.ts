import type { DatabaseSync } from "node:sqlite";
import type { Authz, Question } from "unauth/z";
import { placeChain } from "unauth/z";
import { presetsOf } from "./roles.ts";
import { type Asker, identifiersOf } from "./statements.ts";

export function askInSql(
  db: DatabaseSync,
  authz: Authz,
  asker: Asker,
  question: Question,
  at: number,
): boolean | undefined {
  const row = db
    .prepare(
      `WITH RECURSIVE ${identifiersOf(asker)},
       chain(place, depth) AS (SELECT value, key FROM json_each($chain)),
       found AS (
         SELECT kind, subject, value, depth FROM statements JOIN chain USING (place)
         WHERE subject IN (SELECT id FROM identifiers)
           AND (expires_at IS NULL OR expires_at > $at)
       ),
       given(subject, depth, permission) AS (
         SELECT found.subject, found.depth, gives.value ->> '$[1]'
         FROM found JOIN json_each($gives) AS gives ON gives.value ->> '$[0]' = found.value
         WHERE found.kind = 'allow'
         UNION ALL
         SELECT found.subject, found.depth, preset.value ->> '$[1]'
         FROM found JOIN json_each($presets) AS preset ON preset.value ->> '$[0]' = found.value
         WHERE found.kind = 'assign'
         UNION ALL
         SELECT found.subject, found.depth, role.value
         FROM found JOIN roles ON roles.name = found.value, json_each(roles.gives) AS role
         WHERE found.kind = 'assign'
           AND found.value NOT IN (SELECT value FROM json_each($names))
           AND role.value IN (SELECT value FROM json_each($wanted))
       ),
       removed(subject, depth, permission) AS (
         SELECT found.subject, found.depth, removes.value ->> '$[1]'
         FROM found JOIN json_each($removes) AS removes ON removes.value ->> '$[0]' = found.value
         WHERE found.kind = 'exclude'
       )
       SELECT
         EXISTS (
           SELECT 1 FROM found JOIN roles ON roles.name = found.value
           WHERE found.kind = 'assign' AND roles.catalog <> $catalog
         ) AS stale,
         EXISTS (
           SELECT 1 FROM found
           WHERE kind = 'deny' AND value IN (SELECT value FROM json_each($deny))
         ) AS denied,
         EXISTS (
           SELECT 1 FROM given WHERE NOT EXISTS (
             SELECT 1 FROM removed
             WHERE removed.permission = given.permission
               AND removed.depth <= given.depth
               AND removed.subject IN (given.subject, $subject)
           )
         ) AS kept`,
    )
    .get({
      subject: asker.subject,
      at,
      chain: JSON.stringify(placeChain(question.place ?? "/")),
      catalog: authz.catalog.fingerprint,
      ...tablesOf(authz, question.permission),
    });
  if (row === undefined || row.stale === 1) return undefined;
  return row.denied === 0 && row.kept === 1;
}

function tablesOf(authz: Authz, permission: string): Record<string, string> {
  const related = authz.relatedValues(permission);
  const wanted = related.allow.filter((value) => !value.includes("*"));
  const names = presetsOf(authz);
  return {
    deny: JSON.stringify(related.deny),
    wanted: JSON.stringify(wanted),
    gives: JSON.stringify(
      wanted.flatMap((given) => spellings(given).map((value) => [value, given])),
    ),
    removes: JSON.stringify(
      wanted.flatMap((given) => authz.relatedValues(given).deny.map((value) => [value, given])),
    ),
    presets: JSON.stringify(
      names.flatMap((name) =>
        authz
          .resolveRole(name)
          .filter((given) => wanted.includes(given))
          .map((given) => [name, given]),
      ),
    ),
    names: JSON.stringify(names),
  };
}

function spellings(permission: string): string[] {
  const [resource, action] = permission.split(":");
  return [permission, `${resource}:*`, `*:${action}`, "*"];
}
