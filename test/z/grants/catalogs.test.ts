import { describe, expect, it } from "vitest";
import { ask } from "../../../src/z/ask.ts";
import { type Catalog, type CatalogData, defineCatalog } from "../../../src/z/catalog.ts";
import { could, issueGrants } from "../../../src/z/grants.ts";
import { placeFits } from "../../../src/z/place.ts";
import type {
  Decision,
  GrantsPart,
  Question,
  Statement,
  StoredRole,
} from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

const MONDAY = 1794214800;
const THURSDAY = 1794441600;
const FRIDAY = 1794528000;
const TIMES = [MONDAY, THURSDAY, FRIDAY, FRIDAY + 86400];
const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";
const PLACES = [
  "/",
  ACME,
  ARCHIVES,
  `${ARCHIVES}/archive=2019`,
  "/org=acme/unit=u7",
  "/org=globex",
];
const BY_NAME: GrantsPart[] = ["presets"];

const C1 = {
  permissions: [
    "report:list",
    "report:read",
    "report:write",
    "audit:delete",
    "chat:read",
    "chat:send",
    "file:read",
  ],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: {
    viewer: ["report:read", "file:read"],
    writer: ["viewer", "report:write"],
    player: ["chat:*"],
  },
  places: { "/": ["org"], "org": ["unit", "area"], "area": ["archive"] },
} satisfies CatalogData;
const issuedUnder = defineCatalog(C1);

function changed(data: Partial<CatalogData>): Catalog {
  return defineCatalog({ ...C1, ...data });
}

interface World {
  readonly statements: readonly Statement[];
  readonly roles?: readonly StoredRole[];
}

interface Asker {
  readonly subject: string;
  readonly groups?: readonly string[];
  readonly bases?: readonly string[];
}

function readOf(world: World, asker: Asker) {
  const identifiers = new Set([asker.subject, ...(asker.groups ?? [])]);
  return {
    subject: asker.subject,
    statements: world.statements.filter(({ subject }) => identifiers.has(subject)),
    roles: world.roles,
  };
}

function issueFor(world: World, asker: Asker, omit?: GrantsPart[]) {
  return issueGrants(issuedUnder, readOf(world, asker), {
    bases: asker.bases,
    omit,
    now: () => MONDAY * 1000,
  });
}

/**
 * Issues grants under C1, then asks every permission of `later` at every place that fits it and
 * every time, of the grants under `later`, and of the same statements under `later`: with copies,
 * with C1's presets as they were, handed in as stored roles; by name, with the presets as `later`
 * declares them. The stored roles are those of issue either way. Returns every disagreement, and
 * whether both outcomes were met.
 */
function across(later: Catalog, world: World, asker: Asker, omit?: GrantsPart[]) {
  const grants = issueFor(world, asker, omit);
  const byName = omit?.includes("presets") ?? false;
  const { presets = {}, ...rest } = later.data;
  void presets;
  const oracle = byName ? later : defineCatalog(rest);
  const kept = byName
    ? []
    : Object.entries(C1.presets).map(([name, entries]) => ({ name, entries }));
  const read = readOf(world, asker);
  const roles = [...kept, ...(read.roles ?? []).filter(({ name }) => !(name in C1.presets))];
  const bases = asker.bases ?? ["/"];
  const disagreements: string[] = [];
  const tally = { allowed: 0, denied: 0 };
  for (const at of TIMES) {
    const now = () => at * 1000;
    for (const place of PLACES.filter((key) => placeFits(later, key))) {
      for (const permission of later.data.permissions) {
        const carried = could(later, grants, { permission, place }, { now });
        if (!bases.some((base) => base === "/" || place === base || place.startsWith(`${base}/`))) {
          if (carried.covered) disagreements.push(`covered outside ${place}`);
          continue;
        }
        const fresh = ask(oracle, { ...read, roles }, { permission, place }, { now });
        const [one, other] = [JSON.stringify(summary(fresh)), JSON.stringify(summary(carried))];
        if (one !== other) disagreements.push(`${at} ${place} ${permission}: ${one} != ${other}`);
        tally[fresh.allowed ? "allowed" : "denied"]++;
      }
    }
  }
  return {
    disagreements: disagreements.slice(0, 5),
    allowed: tally.allowed > 0,
    denied: tally.denied > 0,
  };
}

const AGREE = { disagreements: [], allowed: true, denied: true };

function summary(decision: Decision) {
  return {
    allowed: decision.allowed,
    covered: decision.covered,
    by: decision.by === undefined ? "nothing" : decision.by.kind === "deny" ? "deny" : "gives",
  };
}

function couldAt(
  later: Catalog,
  grants: unknown,
  question: Question,
  at = MONDAY,
): Decision<Omit<Statement, "subject">> {
  return could(later, grants, question, { now: () => at * 1000 });
}

const ana: World = {
  statements: [
    { kind: "allow", subject: "ana", value: "report:*", place: ACME },
    { kind: "allow", subject: "ana", value: "*", place: "/org=globex" },
    { kind: "deny", subject: "ana", value: "audit:delete", place: ACME },
    { kind: "allow", subject: "ana", value: "chat:send" },
    { kind: "assign", subject: "ana", value: "player", place: "/org=acme/unit=u7" },
    { kind: "assign", subject: "ana", value: "auditor", place: ACME, expiresAt: FRIDAY },
    { kind: "exclude", subject: "ana", value: "report:write", place: ARCHIVES },
    { kind: "allow", subject: "ana", value: "report:write", place: `${ARCHIVES}/archive=2019` },
    { kind: "assign", subject: "team", value: "writer", place: ACME },
    { kind: "exclude", subject: "team", value: "file:read", place: ARCHIVES },
  ],
  roles: [{ name: "auditor", entries: ["viewer", "audit:delete", "-file:read"] }],
};
const asker = { subject: "ana", groups: ["team"] };

describe.each([
  ["with copies", undefined],
  ["by name", BY_NAME],
])("grants issued under one catalog and read under another, %s", (_, omit) => {
  it("give a permission added since to whoever holds a pattern that matches it", () => {
    const later = changed({ permissions: [...C1.permissions, "report:export", "chat:react"] });
    expect(across(later, ana, asker, omit)).toStrictEqual(AGREE);
    const grants = issueFor(ana, asker, omit);
    expect(couldAt(later, grants, { permission: "report:export", place: ACME }).allowed).toBe(true);
    expect(
      couldAt(later, grants, { permission: "chat:react", place: "/org=acme/unit=u7" }).allowed,
    ).toBe(true);
    expect(couldAt(later, grants, { permission: "chat:react", place: ACME }).allowed).toBe(false);
  });

  it("let a deny of a permission removed since block nothing, and block again once it is declared again", () => {
    const without = changed({ permissions: C1.permissions.filter((p) => p !== "audit:delete") });
    expect(across(without, ana, asker, omit)).toStrictEqual(AGREE);
    const grants = issueFor(ana, asker, omit);
    expect(refused(() => couldAt(without, grants, { permission: "audit:delete" })).code).toBe(
      "ERR_AUTHZ_PERMISSION_UNKNOWN",
    );
    const again = changed({ permissions: [...C1.permissions, "chat:react"] });
    expect(across(again, ana, asker, omit)).toStrictEqual(AGREE);
    expect(couldAt(again, grants, { permission: "audit:delete", place: ACME }).by).toMatchObject({
      kind: "deny",
      value: "audit:delete",
    });
    expect(
      couldAt(again, grants, { permission: "audit:delete", place: "/org=globex" }).allowed,
    ).toBe(true);
  });

  it("follow an implication added since, for what gives and what blocks", () => {
    const later = changed({ implies: { ...C1.implies, "chat:send": ["chat:read"] } });
    expect(across(later, ana, asker, omit)).toStrictEqual(AGREE);
    const grants = issueFor(ana, asker, omit);
    expect(couldAt(issuedUnder, grants, { permission: "chat:read" }).allowed).toBe(false);
    expect(couldAt(later, grants, { permission: "chat:read" }).by).toMatchObject({
      kind: "allow",
      value: "chat:send",
    });
  });

  it("drop an implication removed since", () => {
    const later = changed({ implies: { "report:write": ["report:read"] } });
    expect(across(later, ana, asker, omit)).toStrictEqual(AGREE);
    const grants = issueFor(
      { statements: [{ kind: "allow", subject: "ana", value: "report:read", place: ACME }] },
      { subject: "ana" },
      omit,
    );
    expect(couldAt(issuedUnder, grants, { permission: "report:list", place: ACME }).allowed).toBe(
      true,
    );
    expect(couldAt(later, grants, { permission: "report:list", place: ACME }).allowed).toBe(false);
  });

  it("read a place that no longer fits the structure as inert, and apply it again once it fits", () => {
    const flatter = changed({ places: { "/": ["org"], "org": ["unit"] } });
    expect(across(flatter, ana, asker, omit)).toStrictEqual(AGREE);
    const grants = issueFor(ana, asker, omit);
    expect(
      refused(() => couldAt(flatter, grants, { permission: "report:write", place: ARCHIVES })).code,
    ).toBe("ERR_AUTHZ_PLACE_OUTSIDE");
    const again = changed({
      places: { "/": ["org"], "org": ["unit", "area"], "area": ["archive"], "unit": ["desk"] },
    });
    expect(across(again, ana, asker, omit)).toStrictEqual(AGREE);
    expect(couldAt(again, grants, { permission: "report:write", place: ARCHIVES }).allowed).toBe(
      false,
    );
    expect(
      couldAt(again, grants, { permission: "report:write", place: `${ARCHIVES}/archive=2019` })
        .allowed,
    ).toBe(true);
  });
});

describe("a preset changed or removed since issue", () => {
  const narrower = changed({ presets: { ...C1.presets, viewer: ["file:read"] } });
  const gone = changed({ presets: { viewer: C1.presets.viewer, writer: C1.presets.writer } });

  it("is read from the copy: the subject keeps what the preset gave at issue", () => {
    expect(across(narrower, ana, asker)).toStrictEqual(AGREE);
    const grants = issueFor(ana, asker);
    expect(couldAt(narrower, grants, { permission: "report:read", place: ACME }).allowed).toBe(
      true,
    );
    expect(
      couldAt(narrower, grants, { permission: "report:read", place: ACME }).diverged,
    ).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["viewer"],
    });
  });

  it("is read from the copy once removed, and named as diverged", () => {
    expect(across(gone, ana, asker)).toStrictEqual(AGREE);
    const grants = issueFor(ana, asker);
    const decision = couldAt(gone, grants, { permission: "chat:read", place: "/org=acme/unit=u7" });
    expect(decision).toMatchObject({ allowed: true, by: { kind: "assign", value: "player" } });
    expect(decision.diverged).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: ["player"],
    });
  });

  it("names no copy when the subject holds none of the presets that changed", () => {
    const zed: World = { statements: [{ kind: "assign", subject: "zed", value: "player" }] };
    expect(across(narrower, zed, { subject: "zed" })).toStrictEqual(AGREE);
    const grants = issueFor(zed, { subject: "zed" });
    expect(couldAt(narrower, grants, { permission: "chat:send" }).diverged).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: [],
    });
  });

  it("is read from the catalog in force where the grants carry presets by name", () => {
    expect(across(narrower, ana, asker, BY_NAME)).toStrictEqual(AGREE);
    expect(across(gone, ana, asker, BY_NAME)).toStrictEqual(AGREE);
    const grants = issueFor(ana, asker, BY_NAME);
    const reading = { permission: "report:read", place: "/org=acme/unit=u7" } as const;
    expect(couldAt(issuedUnder, grants, reading).allowed).toBe(true);
    expect(couldAt(narrower, grants, reading).by).toMatchObject({
      kind: "allow",
      value: "report:*",
    });
    const chat = { permission: "chat:read", place: "/org=acme/unit=u7" } as const;
    expect(couldAt(issuedUnder, grants, chat).by).toMatchObject({ value: "player" });
    expect(couldAt(gone, grants, chat)).toMatchObject({
      allowed: false,
      diverged: { segments: ["presets"], permissions: [], presets: [] },
    });
  });

  it("reads grants by name that name no preset at all, as the statements answer", () => {
    const plain: World = {
      statements: [
        { kind: "allow", subject: "ivy", value: "report:write", place: ACME },
        { kind: "assign", subject: "ivy", value: "desk", place: ACME },
      ],
      roles: [{ name: "desk", entries: ["chat:*", "-chat:send"] }],
    };
    expect(across(narrower, plain, { subject: "ivy" }, BY_NAME)).toStrictEqual(AGREE);
    const grants = issueFor(plain, { subject: "ivy" }, BY_NAME);
    expect(couldAt(gone, grants, { permission: "chat:read", place: ACME }).by).toMatchObject({
      value: "desk",
    });
  });
});

describe("a stored role that references a preset", () => {
  const auditor: World = {
    statements: [{ kind: "assign", subject: "ada", value: "auditor", place: ACME }],
    roles: [{ name: "auditor", entries: ["viewer", "audit:delete", "-file:read"] }],
  };
  const narrower = changed({ presets: { ...C1.presets, viewer: ["file:read"] } });
  const wider = changed({ permissions: [...C1.permissions, "file:share"] });

  it("travels with the copy it references, and reads it as at issue", () => {
    expect(across(narrower, auditor, { subject: "ada" })).toStrictEqual(AGREE);
    const grants = issueFor(auditor, { subject: "ada" });
    expect(grants.ps).toStrictEqual({ viewer: [1, 2] });
    expect(couldAt(narrower, grants, { permission: "report:list", place: ACME }).by).toStrictEqual({
      kind: "assign",
      value: "auditor",
      place: ACME,
    });
  });

  it("names the preset by name and reads it as the catalog in force declares it", () => {
    const grants = issueFor(auditor, { subject: "ada" }, BY_NAME);
    expect(grants).not.toHaveProperty("ps");
    expect(across(narrower, auditor, { subject: "ada" }, BY_NAME)).toStrictEqual(AGREE);
    const list = { permission: "report:list", place: ACME } as const;
    expect(couldAt(issuedUnder, grants, list).allowed).toBe(true);
    expect(couldAt(narrower, grants, list).allowed).toBe(false);
    expect(across(wider, auditor, { subject: "ada" }, BY_NAME)).toStrictEqual(AGREE);
    expect(
      couldAt(wider, grants, { permission: "audit:delete", place: ACME }).diverged,
    ).toStrictEqual({
      segments: ["permissions"],
      permissions: [],
      presets: [],
    });
  });
});
