import { type Catalog, defineCatalog } from "../../../src/z/catalog.ts";
import type { Change } from "../../../src/z/change.ts";
import { placeKey } from "../../../src/z/place.ts";
import type { Statement } from "../../../src/z/types.ts";
import { applyChange, applyGenesis } from "./change.ts";
import { putMemberships, putRepo, putTeam, type Repo } from "./content.ts";
import { CountedDatabase } from "./database.ts";
import { createSchema } from "./schema.ts";

/** A forge: organisations hold repositories. */
export const forge: Catalog = defineCatalog({
  permissions: [
    "access:manage",
    "repo:read",
    "repo:write",
    "repo:admin",
    "issue:read",
    "issue:write",
    "billing:read",
    "settings:edit",
  ],
  implies: {
    "repo:admin": ["repo:write"],
    "repo:write": ["repo:read"],
    "issue:write": ["issue:read"],
  },
  presets: {
    reader: ["repo:read", "issue:read"],
    writer: ["reader", "repo:write", "issue:write"],
    maintainer: ["writer", "repo:admin", "access:manage"],
    owner: ["*"],
  },
  places: { "/": ["org"], "org": ["repo"] },
  manager: "access:manage",
});

export const NOW = 1794214800;
export const DAY = 86400;
export const TIMES: readonly number[] = [NOW, NOW + 8 * DAY, NOW + 31 * DAY];

export const ACME: string = placeKey({ org: "acme" });
export const GLOBEX: string = placeKey({ org: "globex" });
export const API: string = placeKey({ repo: "api" }, { under: ACME });
export const WEB: string = placeKey({ repo: "web" }, { under: ACME });
export const VAULT: string = placeKey({ repo: "vault" }, { under: ACME });
export const CORE: string = placeKey({ repo: "core" }, { under: GLOBEX });
export const LEGACY: string = placeKey({ repo: "legacy" }, { under: GLOBEX });
export const PLACES: readonly string[] = [
  "/",
  ACME,
  API,
  WEB,
  VAULT,
  placeKey({ repo: "new" }, { under: ACME }),
  GLOBEX,
  CORE,
  LEGACY,
  placeKey({ org: "initech" }),
];

/** Pat's groups as the application knows them: a team counts for the teams above it. */
export const PAT_GROUPS: readonly string[] = ["acme-all", "acme-api", "acme-eng", "globex-all"];

export const REPOS: readonly Repo[] = [
  { org: "acme", name: "api", visibility: "private" },
  { org: "acme", name: "web", visibility: "public" },
  { org: "acme", name: "vault", visibility: "private" },
  { org: "globex", name: "core", visibility: "private" },
  { org: "globex", name: "legacy", visibility: "public" },
];

const place = (statement: Statement): Change => ({ action: "place", statement });

/** Every statement and stored role of the world, each written through the change path by its author. */
export const CHANGES: readonly (readonly [author: string, change: Change])[] = [
  ["root", place({ kind: "allow", subject: "ops", value: "*" })],
  ["root", place({ kind: "assign", subject: "ann", value: "owner", place: ACME })],
  ["root", place({ kind: "assign", subject: "gwen", value: "owner", place: GLOBEX })],
  ["root", place({ kind: "assign", subject: "staff", value: "reader" })],
  [
    "ann",
    { action: "define", role: { name: "triager", home: ACME, entries: ["reader", "issue:write"] } },
  ],
  [
    "ann",
    { action: "define", role: { name: "lead", home: ACME, entries: ["triager", "repo:admin"] } },
  ],
  ["ann", place({ kind: "assign", subject: "acme-all", value: "reader", place: ACME })],
  ["ann", place({ kind: "assign", subject: "acme-eng", value: "triager", place: ACME })],
  ["ann", place({ kind: "assign", subject: "acme-api", value: "lead", place: API })],
  ["ann", place({ kind: "exclude", subject: "acme-all", value: "issue:*", place: VAULT })],
  ["ann", place({ kind: "deny", subject: "pat", value: "repo:admin", place: WEB })],
  [
    "ann",
    place({
      kind: "allow",
      subject: "pat",
      value: "billing:read",
      place: ACME,
      expiresAt: NOW + 30 * DAY,
    }),
  ],
  ["ann", place({ kind: "assign", subject: "sam", value: "reader", place: WEB })],
  ["gwen", place({ kind: "assign", subject: "globex-all", value: "writer", place: GLOBEX })],
  ["gwen", place({ kind: "assign", subject: "pat", value: "maintainer", place: CORE })],
  ["gwen", place({ kind: "deny", subject: "pat", value: "repo:write", place: LEGACY })],
  [
    "gwen",
    place({
      kind: "allow",
      subject: "globex-all",
      value: "settings:edit",
      place: CORE,
      expiresAt: NOW + 7 * DAY,
    }),
  ],
];

/** The application's data, then genesis about `root`, then every change of {@link CHANGES}. */
export function seed(): CountedDatabase {
  const db = CountedDatabase.create();
  createSchema(db);
  putTeam(db, "acme-all");
  putTeam(db, "acme-eng", "acme-all");
  putTeam(db, "acme-api", "acme-eng");
  putTeam(db, "globex-all");
  putMemberships(db, "pat", ["acme-api", "globex-all"]);
  putMemberships(db, "sam", ["acme-all"]);
  for (const repo of REPOS) putRepo(db, repo);
  applyGenesis(db, forge, { kind: "allow", subject: "root", value: "*" }, NOW);
  for (const [subject, change] of CHANGES) applyChange(db, forge, { subject, at: NOW }, change);
  return db;
}
