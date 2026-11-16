import { afterAll, describe, expect, it } from "vitest";
import { defineCatalog } from "../../../src/z/catalog.ts";
import { ask } from "../../../src/z/ask.ts";
import { could, issueGrants } from "../../../src/z/grants.ts";
import { placeKey } from "../../../src/z/place.ts";
import type { Decision, Statement } from "../../../src/z/types.ts";
import { CountedDatabase } from "./_sqlite/database.ts";
import { gather } from "./_sqlite/gather.ts";
import { placesOnChain, placesUnder } from "./_sqlite/places.ts";
import { createSchema, insertStatements } from "./_sqlite/schema.ts";

const NOW = 1794214800;

const catalog = defineCatalog({
  permissions: ["doc:read", "doc:write", "doc:delete", "access:manage"],
  implies: { "doc:write": ["doc:read"] },
  presets: { editor: ["doc:write"], owner: ["*"] },
});

type Permission = (typeof catalog.data.permissions)[number];

const ORGS = [
  "acme",
  "acme-x",
  "acme.x",
  "acme0",
  "a_me",
  "ac%e",
  "ac%25e",
  "ACME",
  "東京",
  "café",
];
const LONG = "x".repeat(120);

function placesOf(org: string): string[] {
  const base = placeKey({ org });
  return [
    base,
    placeKey({ unit: "u1" }, { under: base }),
    placeKey({ unit: "u10" }, { under: base }),
    placeKey({ unit: "u1-x" }, { under: base }),
    placeKey({ unit: "u1", project: "p1" }, { under: base }),
    placeKey(
      [
        ["unit", "u1"],
        ["project", "p1"],
        ["folder", "f"],
        ["folder", "f"],
      ],
      { under: base },
    ),
    placeKey({ folder: "%e", doc: "1" }, { under: base }),
    placeKey({ folder: "_" }, { under: base }),
    placeKey({ folder: `${LONG}a`, doc: "1" }, { under: base }),
    placeKey({ folder: `${LONG}b`, doc: "1" }, { under: base }),
    placeKey({ folder: LONG }, { under: base }),
  ];
}

const KEYS = ["/", ...ORGS.flatMap(placesOf)];
const A_ME = placeKey({ org: "a_me" });
const AC_E = placeKey({ org: "ac%e" });

const SHAPES: readonly Omit<Statement, "subject" | "place">[] = [
  { kind: "assign", value: "editor" },
  { kind: "deny", value: "doc:delete" },
  { kind: "allow", value: "doc:delete" },
  { kind: "exclude", value: "doc:write" },
  { kind: "allow", value: "doc:*" },
  { kind: "deny", value: "doc:read" },
  { kind: "exclude", value: "doc:read" },
  { kind: "allow", value: "*" },
  { kind: "deny", value: "doc:write", expiresAt: NOW + 3600 },
  { kind: "allow", value: "doc:write" },
  { kind: "exclude", value: "*" },
];

const STATEMENTS: Statement[] = [
  { kind: "allow", subject: "sam", value: "doc:read", place: "/" },
  ...ORGS.flatMap((org) =>
    placesOf(org).map((place, index) => ({ ...SHAPES[index]!, subject: "sam", place })),
  ),
  ...KEYS.map((place): Statement => ({ kind: "allow", subject: "eve", value: "*", place })),
];

const db = CountedDatabase.create();
createSchema(db);
insertStatements(db, STATEMENTS);
afterAll(() => db.close());

function segments(key: string): string[] {
  return key === "/" ? [] : key.slice(1).split("/");
}

function continues(longer: readonly string[], shorter: readonly string[]): boolean {
  return shorter.length <= longer.length && shorter.every((part, index) => part === longer[index]);
}

function identity(statement: Statement): string {
  return JSON.stringify([statement.kind, statement.subject, statement.value, statement.place]);
}

function covers(outer: string, inner: string): boolean {
  return continues(segments(inner), segments(outer));
}

function expectedUnder(key: string): string[] {
  const own = segments(key);
  return KEYS.filter((other) => {
    const parts = segments(other);
    return parts.length > own.length && continues(parts, own);
  }).toSorted();
}

function expectedChain(key: string): string[] {
  return KEYS.filter((other) => continues(segments(key), segments(other))).toSorted();
}

function summary(decision: Decision) {
  return {
    allowed: decision.allowed,
    covered: decision.covered,
    by: decision.by === undefined ? "nothing" : decision.by.kind === "deny" ? "deny" : "gives",
  };
}

const answers = new Map<string, ReturnType<typeof summary>>();

const SAM = { subject: "sam", statements: STATEMENTS.filter(({ subject }) => subject === "sam") };

/** The answer of every statement about Sam, computed once per question. */
function whole(permission: Permission, place: string, at: number): ReturnType<typeof summary> {
  const id = `${at} ${place} ${permission}`;
  let answer = answers.get(id);
  if (answer === undefined) {
    answer = summary(ask(catalog, SAM, { permission, place }, { now: () => at * 1000 }));
    answers.set(id, answer);
  }
  return answer;
}

describe("a set of keys built to collide", () => {
  it("holds siblings that sort between a key and the places under it", () => {
    const acme = placeKey({ org: "acme" });
    expect(KEYS).toHaveLength(1 + ORGS.length * 11);
    expect(new Set(KEYS).size).toBe(KEYS.length);
    expect("/org=acme-x" > acme && "/org=acme-x" < `${acme}/unit=u1`).toBe(true);
    expect("/org=acme.x" > acme && "/org=acme.x" < `${acme}/unit=u1`).toBe(true);
    expect(KEYS).toContain("/org=acme0");
    expect(KEYS).toContain("/org=ac%25e");
    expect(KEYS).toContain("/org=ac%2525e");
    expect(KEYS).toContain("/org=%E6%9D%B1%E4%BA%AC");
  });
});

describe("selecting places by byte range and by chain", () => {
  it("the range of every key returns exactly the places under it", () => {
    const found = Object.fromEntries(KEYS.map((key) => [key, placesUnder(db, key).toSorted()]));
    const expected = Object.fromEntries(KEYS.map((key) => [key, expectedUnder(key)]));
    expect(found).toStrictEqual(expected);
  });

  it("the chain of every key returns exactly the places covering it", () => {
    const found = Object.fromEntries(KEYS.map((key) => [key, placesOnChain(db, key).toSorted()]));
    const expected = Object.fromEntries(KEYS.map((key) => [key, expectedChain(key)]));
    expect(found).toStrictEqual(expected);
  });

  it("returns nothing of an organisation whose name only starts like another", () => {
    expect(placesUnder(db, "/org=acme").every((key) => key.startsWith("/org=acme/"))).toBe(true);
    expect(placesUnder(db, "/org=acme")).toHaveLength(10);
    expect(placesUnder(db, A_ME)).toHaveLength(10);
    expect(placesUnder(db, AC_E)).toHaveLength(10);
  });
});

describe("grants issued from the rows a store returns for one base", () => {
  const permissions = catalog.data.permissions;

  it.each(ORGS.map((org) => placeKey({ org })))(
    "for %s read only that organisation's rows, hold only its places and answer as every statement does",
    (base) => {
      const read = gather(db, "sign-in", { subject: "sam", at: NOW, chain: [base], under: [base] });
      const rows = STATEMENTS.filter(
        ({ subject, place = "/" }) =>
          subject === "sam" && (covers(place, base) || covers(base, place)),
      );
      expect(read.statements.map(identity).toSorted()).toStrictEqual(rows.map(identity).toSorted());
      const grants = issueGrants(catalog, read, { bases: [base], now: () => NOW * 1000 });
      expect(grants.pl?.toSorted()).toStrictEqual(expectedUnder(base).concat(base).toSorted());

      const mismatches: string[] = [];
      const outcomes = new Set<boolean>();
      for (const at of [NOW, NOW + 7200]) {
        const now = () => at * 1000;
        for (const place of KEYS) {
          for (const permission of permissions) {
            const carried = summary(could(catalog, grants, { permission, place }, { now }));
            const expected = covers(base, place)
              ? whole(permission, place, at)
              : { allowed: false, covered: false, by: "nothing" };
            if (expected.covered) outcomes.add(expected.allowed);
            if (JSON.stringify(carried) !== JSON.stringify(expected)) {
              mismatches.push(`${at} ${place} ${permission}`);
            }
          }
        }
      }
      expect(mismatches).toStrictEqual([]);
      expect(outcomes).toStrictEqual(new Set([true, false]));
    },
  );

  it("a question asked of the rows on the chain answers as every statement does, at every key", () => {
    const mismatches: string[] = [];
    for (const place of KEYS) {
      const read = gather(db, "question", { subject: "sam", at: NOW, chain: [place], under: [] });
      for (const permission of catalog.data.permissions) {
        const now = () => NOW * 1000;
        const narrow = summary(ask(catalog, read, { permission, place }, { now }));
        if (JSON.stringify(narrow) !== JSON.stringify(whole(permission, place, NOW))) {
          mismatches.push(`${place} ${permission}`);
        }
      }
    }
    expect(mismatches).toStrictEqual([]);
  });
});

describe("the selection the byte range replaces", () => {
  function orgsMatchedByLike(key: string): string[] {
    const rows = db.read(
      "like",
      "SELECT DISTINCT place FROM statements WHERE place LIKE $pattern",
      { pattern: `${key}/%` },
    );
    return [...new Set(rows.map((row) => segments(String(row.place))[0]!))].toSorted();
  }

  it("is avoided: LIKE reads `_` in /org=a_me as any character and folds case, returning acme and ACME", () => {
    expect(orgsMatchedByLike(A_ME)).toStrictEqual(["org=ACME", "org=a_me", "org=acme"].toSorted());
  });

  it("is avoided: LIKE reads `%` in /org=ac%25e as any run of characters, returning other organisations", () => {
    expect(orgsMatchedByLike(AC_E)).toStrictEqual(
      [
        "org=ACME",
        "org=ac%2525e",
        "org=ac%25e",
        "org=acme",
        "org=acme-x",
        "org=acme.x",
        "org=acme0",
      ].toSorted(),
    );
  });
});

describe("collation", () => {
  it("is avoided: a column that folds case makes ACME and acme one place and Sam and sam one subject", () => {
    db.define(
      "nocase",
      "CREATE TABLE nocase (subject TEXT COLLATE NOCASE, place TEXT COLLATE NOCASE)",
    );
    for (const [subject, place] of [
      ["sam", "/org=acme"],
      ["Sam", "/org=ACME"],
      ["sam", "/org=acme/unit=u1"],
      ["sam", "/org=ACME/unit=u1"],
    ] as const) {
      db.write("nocase.insert", "INSERT INTO nocase VALUES ($subject, $place)", { subject, place });
    }
    const exact = db.read("nocase.place", "SELECT place FROM nocase WHERE place = '/org=acme'");
    expect(exact.map((row) => String(row.place)).toSorted()).toStrictEqual([
      "/org=ACME",
      "/org=acme",
    ]);
    const under = db.read(
      "nocase.under",
      "SELECT place FROM nocase WHERE place > '/org=acme/' AND place < '/org=acme0'",
    );
    expect(under.map((row) => String(row.place)).toSorted()).toStrictEqual([
      "/org=ACME/unit=u1",
      "/org=acme/unit=u1",
    ]);
    const subjects = db.read("nocase.subject", "SELECT subject FROM nocase WHERE subject = 'sam'");
    expect(subjects).toHaveLength(4);
  });

  it("the store's own columns keep ACME and acme, Sam and sam apart", () => {
    insertStatements(db, [
      { kind: "allow", subject: "Sam", value: "doc:read", place: "/org=ACME" },
    ]);
    const exact = db.read(
      "statements.place",
      "SELECT DISTINCT place FROM statements WHERE place = '/org=acme'",
    );
    expect(exact.map((row) => row.place)).toStrictEqual(["/org=acme"]);
    const subjects = db.read(
      "statements.subject",
      "SELECT DISTINCT subject FROM statements WHERE subject = 'sam'",
    );
    expect(subjects.map((row) => row.subject)).toStrictEqual(["sam"]);
    expect(placesUnder(db, "/org=acme").some((key) => key.startsWith("/org=ACME"))).toBe(false);
  });
});
