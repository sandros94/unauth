import type { DatabaseSync } from "node:sqlite";
import { assertRole } from "unauth/z";
import { transaction } from "../../application/db.ts";
import { readRoles, writeRole } from "../../storage/roles.ts";
import { CAPABILITIES as cap, type Permission, authz } from "./authz.ts";

export type Capabilities = readonly (Permission | "*")[];

const subscriber: Capabilities = [cap.read];
const contributor: Capabilities = [...subscriber, cap.edit_posts, cap.delete_posts];
const author: Capabilities = [...contributor, cap.edit_published_posts, cap.publish_posts];
const editor: Capabilities = [...author, cap.edit_others_posts, cap.read_private_posts];

export const DEFAULT_ROLES: Readonly<Record<string, Capabilities>> = {
  administrator: ["*"],
  editor,
  author,
  contributor,
  subscriber,
};

export function populateRoles(db: DatabaseSync): void {
  for (const [name, entries] of Object.entries(DEFAULT_ROLES)) addRole(db, name, entries);
}

export function addRole(db: DatabaseSync, name: string, entries: readonly string[]): void {
  transaction(db, () => {
    const roles = readRoles(db);
    const role = { name, entries };
    assertRole(authz.catalog, role, { roles });
    writeRole(db, authz, role, roles);
  });
}

export function addCap(db: DatabaseSync, name: string, capability: Permission): void {
  const role = readRoles(db, [name])[0];
  if (role === undefined) throw new Error(`No role ${name}.`);
  addRole(db, name, [...role.entries, capability]);
}

export function resetRole(db: DatabaseSync, name: string): void {
  const defaults = DEFAULT_ROLES[name];
  if (defaults === undefined) throw new Error(`${name} is not a default role.`);
  addRole(db, name, defaults);
}
