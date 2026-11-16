import type { DatabaseSync } from "node:sqlite";
import { type H3Event, HTTPError } from "h3";
import type { Authz, Grants } from "unauth/z";
import { type Asker, readForGrants } from "../storage/statements.ts";
import { userExists } from "../storage/users.ts";
import { useDB } from "./db.ts";
import { readBody, textOf } from "./http.ts";

export function grantsFor(
  db: DatabaseSync,
  authz: Authz,
  asker: Asker,
  options: { bases?: readonly string[] } = {},
): Grants {
  const now = Date.now();
  const bases = options.bases ?? ["/"];
  const read = readForGrants(db, asker, { bases, at: Math.floor(now / 1000) });
  return authz.issueGrants(read, { bases, now: () => now });
}

export async function standInUser(event: H3Event): Promise<string> {
  const user = textOf(await readBody(event), "user");
  if (!userExists(useDB(event), user)) {
    throw new HTTPError({ status: 401, message: "No such user." });
  }
  return user;
}
