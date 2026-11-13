import type { DatabaseSync } from "node:sqlite";
import type { Authz, StoredRole } from "unauth/z";
import { roleOf } from "./rows.ts";

export function readRoles(db: DatabaseSync, names?: readonly string[]): StoredRole[] {
  const rows =
    names === undefined
      ? db.prepare("SELECT name, entries FROM roles").all()
      : db
          .prepare("SELECT name, entries FROM roles WHERE name IN (SELECT value FROM json_each(?))")
          .all(JSON.stringify(names));
  return rows.map((row) => roleOf(row));
}

export function writeRole(
  db: DatabaseSync,
  authz: Authz,
  role: StoredRole,
  roles: readonly StoredRole[],
): void {
  const next = [...roles.filter(({ name }) => name !== role.name), role];
  const resolved = next.map(({ name }) => [name, authz.resolveRole(name, { roles: next })]);
  db.prepare(
    `INSERT INTO roles (name, entries, gives, catalog) VALUES (?, ?, '[]', '')
     ON CONFLICT (name) DO UPDATE SET entries = excluded.entries`,
  ).run(role.name, JSON.stringify(role.entries));
  db.prepare(
    `UPDATE roles SET catalog = $catalog, gives = (
       SELECT value ->> '$[1]' FROM json_each($resolved) WHERE value ->> '$[0]' = roles.name
     )`,
  ).run({ catalog: authz.catalog.fingerprint, resolved: JSON.stringify(resolved) });
}

export function presetsOf(authz: Authz): string[] {
  return Object.keys(authz.catalog.data.presets ?? {});
}
