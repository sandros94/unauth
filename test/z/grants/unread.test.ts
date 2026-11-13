import { describe, expect, it } from "vitest";
import { ask } from "../../../src/z/ask.ts";
import { type CatalogData, defineCatalog } from "../../../src/z/catalog.ts";
import { assertGrants, could, diverged, issueGrants } from "../../../src/z/grants.ts";
import type { Question, Statement, StoredRole } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

const MONDAY = 1794214800;
const THURSDAY = 1794441600;
const S1 = "/server=s1";
const LOBBY = "/server=s1/channel=lobby";
const ACME = "/org=acme";

const data = {
  permissions: [
    "report:list",
    "report:read",
    "report:write",
    "chat:read",
    "chat:send",
    "match:join",
  ],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: {
    writer: ["report:write", "chat:send"],
    viewer: ["report:read"],
    player: ["chat:*", "match:join"],
  },
  places: { "/": ["org", "server"], "org": ["area", "unit"], "server": ["channel"] },
} satisfies CatalogData;
const catalog = defineCatalog(data);
const ct = catalog.fingerprint;
const now = () => MONDAY * 1000;

function read(grants: unknown, question: Question, at = MONDAY) {
  return could(catalog, grants, question, { now: () => at * 1000 });
}

const send = { permission: "chat:send", place: LOBBY } as const;

/**
 * Lea, as a server's grants hold her: the stored role `desk` at the server, which names the copy
 * of `player`, and `report:write` given at the organisation.
 */
const lea = {
  v: "1",
  ct,
  at: MONDAY,
  pl: [S1, ACME],
  pm: ["chat:send", "match:join", "report:write"],
  ps: { player: ["chat:*", 1], writer: [2, 0] },
  sr: { desk: ["player"] },
  nt: { "desk": { a: [[0]] }, "2": { a: [[1]] } },
};
const answer = { allowed: true, covered: true, by: { kind: "assign", value: "desk", place: S1 } };

describe("a read of grants looks only where its question looks (Section 8.3)", () => {
  const elsewhere: [string, unknown][] = [
    [
      "a malformed entry under a value it does not look up",
      { ...lea, nt: { ...lea.nt, "match:*": { a: {} } } },
    ],
    [
      "an entry of another value under a name out of its form",
      { ...lea, nt: { ...lea.nt, "Bad:Name": { a: [[]] } } },
    ],
    [
      "an item of another entry pointing nowhere",
      { ...lea, nt: { ...lea.nt, "2": { a: [[1], [9]] } } },
    ],
    [
      "a place not canonical that an item off the chain points at",
      { ...lea, pl: [S1, ACME, "/org=acme/"], nt: { ...lea.nt, desk: { a: [[0], [2]] } } },
    ],
    ["a place not canonical nothing points at", { ...lea, pl: [S1, ACME, "/server=S1//"] }],
    ["the root in `pl` where nothing points", { ...lea, pl: [S1, ACME, "/"] }],
    [
      "a broken definition of a role no live covering item names",
      { ...lea, sr: { ...lea.sr, lost: ["Not An Entry"] }, nt: { ...lea.nt, lost: { a: [[1]] } } },
    ],
    [
      "a definition that is not a list, of a role whose item has ended",
      { ...lea, sr: { ...lea.sr, gone: 7 }, nt: { ...lea.nt, gone: { a: [[null, MONDAY]] } } },
    ],
    [
      "a copy that is not read, written with a permission by name",
      { ...lea, ps: { ...lea.ps, writer: ["report:write"] } },
    ],
    ["a non-string in `pm` at a position not looked up", { ...lea, pm: [...lea.pm, 7] }],
    ["a pattern in `pm` at a position not looked up", { ...lea, pm: [...lea.pm, "chat:*"] }],
    [
      "a permission named by name beside `pm`",
      { ...lea, nt: { ...lea.nt, "report:read": { d: [[]] } } },
    ],
    ["a position past `pm`", { ...lea, nt: { ...lea.nt, "9": { d: [[]] } } }],
    ["`*:*`", { ...lea, nt: { ...lea.nt, "*:*": { d: [[]] } } }],
    [
      "an own `__proto__` entry",
      JSON.parse(JSON.stringify(lea).replace('"nt":{', '"nt":{"__proto__":{"d":[[]]},')),
    ],
    ["a role name not a token, with no entry under it", { ...lea, sr: { ...lea.sr, Desk: [] } }],
    [
      "an own `__proto__` copy, with no entry under it",
      JSON.parse(JSON.stringify(lea).replace('"ps":{', '"ps":{"__proto__":[],')),
    ],
    ["a name in both `ps` and `sr`, read as the copy", { ...lea, sr: { ...lea.sr, player: [] } }],
    [
      "a broken copy of a preset the catalog declares, under its own presets",
      { ...lea, ps: { ...lea.ps, player: ["chat:*", "-*:*"] } },
    ],
  ];

  it.each(elsewhere)("answers as if it were not there: %s", (_, grants) => {
    expect(read(grants, send)).toStrictEqual(answer);
    expect(read([lea, grants], send)).toStrictEqual(answer);
  });

  it.each(elsewhere)("is refused whole by `assertGrants`: %s", (_, grants) => {
    expect(refused(() => assertGrants(catalog, grants, { now }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
  });

  const where: [string, unknown][] = [
    [
      "a malformed entry under a value it looks up",
      { ...lea, nt: { ...lea.nt, "chat:*": { a: {} } } },
    ],
    [
      "an entry it looks up with another member",
      { ...lea, nt: { ...lea.nt, "*": { a: [], y: [] } } },
    ],
    ["a deny under a role it tries", { ...lea, nt: { ...lea.nt, viewer: { d: [[]] } } }],
    ["an item it reads pointing nowhere", { ...lea, nt: { ...lea.nt, desk: { a: [[0], [9]] } } }],
    [
      "an item it reads with an end in milliseconds",
      { ...lea, nt: { ...lea.nt, desk: { a: [[0, MONDAY * 1000]] } } },
    ],
    ["a deny it reads with a bundle", { ...lea, nt: { ...lea.nt, "0": { d: [[null, null, 1]] } } }],
    [
      "an ended item of an entry it looks up",
      { ...lea, nt: { ...lea.nt, desk: { a: [[0], [null, MONDAY - 1, 0]] } } },
    ],
    ["an item it reads pointing into a `pl` that is not a list", { ...lea, pl: { 0: S1 } }],
    [
      "a broken definition of the role a live covering item names",
      { ...lea, sr: { desk: ["Not An Entry"] } },
    ],
    [
      "a definition reading a non-string from `pm`",
      { ...lea, sr: { desk: ["player", 3] }, pm: [...lea.pm, 7] },
    ],
    ["the permission it looks up twice in `pm`", { ...lea, pm: [...lea.pm, "chat:send"] }],
    [
      "a role name not a token, with an entry under it",
      { ...lea, sr: { ...lea.sr, Desk: [] }, nt: { ...lea.nt, Desk: { a: [[0]] } } },
    ],
    ["`ps` written as a list", { ...lea, ps: [] }],
    ["`sr` written as a list", { ...lea, sr: [["player"]] }],
    ["`nt` that is a list", { ...lea, nt: [] }],
    ["`pm` that is not a list", { ...lea, pm: {} }],
    ["a base that is not canonical", { ...lea, bs: ["/server=s1/"] }],
  ];

  it.each(where)("is refused as malformed: %s", (_, grants) => {
    expect(refused(() => read(grants, send))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
    expect(refused(() => assertGrants(catalog, grants, { now }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
  });

  it("checks every item of an entry it looks up, in members it does not use for the question", () => {
    const denied = { ...lea, nt: { ...lea.nt, "2": { a: [[1]], d: [[null, null, 1]] } } };
    expect(refused(() => read(denied, { permission: "report:list", place: ACME }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
    expect(read(denied, send)).toStrictEqual(answer);
  });

  it("only compares the place an item points at with the keys of the chain", () => {
    const root = { ...lea, pl: ["/", ACME] };
    expect(read(root, send)).toStrictEqual({ ...answer, by: { ...answer.by, place: "/" } });
    const spelled = { ...lea, pl: ["/server=s1/", ACME] };
    expect(read(spelled, send)).toStrictEqual({ allowed: false, covered: true });
    const percent = { ...lea, pl: ["/server=%731", ACME] };
    expect(read(percent, send)).toStrictEqual({ allowed: false, covered: true });
    for (const grants of [root, spelled, percent]) {
      expect(refused(() => assertGrants(catalog, grants, { now })).code).toBe(
        "ERR_AUTHZ_MALFORMED",
      );
    }
  });

  it("checks `pl` only where an item names a place", () => {
    const rooted = { ...lea, pl: 7, nt: { desk: { a: [[]] } } };
    expect(read(rooted, send)).toStrictEqual({ ...answer, by: { ...answer.by, place: "/" } });
    expect(refused(() => read({ ...lea, pl: 7 }, send)).code).toBe("ERR_AUTHZ_MALFORMED");
  });

  it("checks every permission a resolved definition points at in `pm`, and no other", () => {
    for (const member of ["Chat:Send", "chat:*", 7]) {
      const pointed = { ...lea, pm: [...lea.pm, member], sr: { desk: ["player", 3] } };
      expect(refused(() => read(pointed, send))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "grants" },
      });
      const unpointed = { ...lea, pm: [...lea.pm, member], sr: { ...lea.sr, lost: [3] } };
      expect(read(unpointed, send)).toStrictEqual(answer);
    }
  });

  it("checks every name of `nt` without `pm` once a segment differs, and not under the very catalog", () => {
    const later = defineCatalog({ ...data, presets: { ...data.presets, viewer: ["chat:read"] } });
    const named = {
      v: "1",
      ct,
      at: MONDAY,
      nt: { "chat:send": { a: [[]] }, "Report:read": { d: [[]] } },
    };
    expect(read(named, send).allowed).toBe(true);
    expect(diverged(catalog, named, { now })).toBeUndefined();
    for (const run of [
      () => could(later, named, send, { now }),
      () => diverged(later, named, { now }),
    ]) {
      expect(refused(run)).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "grants" },
      });
    }
    const clean = { ...named, nt: { "chat:send": { a: [[]] }, "chat:*": {}, "desk": {} } };
    expect(diverged(later, clean, { now })).toStrictEqual({
      segments: ["presets"],
      permissions: [],
      presets: [],
    });
  });

  it("refuses the time of issue before entries it would read", () => {
    expect(refused(() => read({ ...lea, nt: [] }, send, MONDAY - 1))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_EARLY",
    });
    expect(
      refused(() => assertGrants(catalog, { ...lea, nt: [] }, { now: () => (MONDAY - 1) * 1000 })),
    ).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
  });
});

describe("role names, looked up in `ps`, then `sr`, then the catalog in force (Section 8.3)", () => {
  it("reads a preset the grants hold no copy of from the catalog, though they hold copies of others", () => {
    const grants = {
      v: "1",
      ct,
      at: MONDAY,
      ps: { player: ["chat:*"] },
      nt: { player: { a: [[]] }, viewer: { a: [[]] } },
    };
    expect(read(grants, { permission: "report:list" })).toStrictEqual({
      allowed: true,
      covered: true,
      by: { kind: "assign", value: "viewer", place: "/" },
    });
    const referenced = { ...grants, sr: { desk: ["player", "viewer"] }, nt: { desk: { a: [[]] } } };
    expect(read(referenced, { permission: "report:read" }).by).toMatchObject({ value: "desk" });
  });

  it("names the copy before the stored role, and the stored role before the catalog's preset, when several give alike", () => {
    const grants = {
      v: "1",
      ct,
      at: MONDAY,
      pm: ["report:read"],
      ps: { writer: [0] },
      sr: { alpha: [0] },
      nt: { alpha: { a: [[]] }, viewer: { a: [[]] }, writer: { a: [[]] } },
    };
    expect(read(grants, { permission: "report:read" }).by).toMatchObject({ value: "writer" });
    const stored = {
      ...grants,
      ps: undefined,
      sr: { zeta: [0] },
      nt: { viewer: { a: [[]] }, zeta: { a: [[]] } },
    };
    expect(read(stored, { permission: "report:read" }).by).toMatchObject({ value: "zeta" });
  });
});

describe("a copy under the catalog's own presets (Section 8.3)", () => {
  const [permissionsSegment] = ct.split(".");
  const otherPresets = `${permissionsSegment}.AAAAAAAAAAA`;
  const differing = {
    v: "1",
    ct,
    at: MONDAY,
    pm: ["match:join"],
    ps: { viewer: [0] },
    nt: { viewer: { a: [[]] } },
  };
  const broken = { ...differing, ps: { viewer: ["*:*"] } };
  const reading = { permission: "report:read" } as const;
  const joining = { permission: "match:join" } as const;

  it("reads the catalog's preset, not the copy, when the second segment matches", () => {
    expect(read(differing, reading)).toStrictEqual({
      allowed: true,
      covered: true,
      by: { kind: "assign", value: "viewer", place: "/" },
    });
    expect(read(differing, joining).allowed).toBe(false);
    expect(() => assertGrants(catalog, differing, { now })).not.toThrow();
  });

  it("does not read a malformed copy when the second segment matches", () => {
    expect(read(broken, reading).by).toMatchObject({ value: "viewer" });
    expect(refused(() => assertGrants(catalog, broken, { now }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
  });

  it("reads a copy the catalog does not declare from the copy", () => {
    const own = { ...differing, ps: { lounge: [0] }, nt: { lounge: { a: [[]] } } };
    expect(read(own, joining).by).toMatchObject({ value: "lounge" });
  });

  it("reads the copy when the second segment differs, and refuses it malformed once resolved", () => {
    expect(read({ ...differing, ct: otherPresets }, joining).allowed).toBe(true);
    expect(read({ ...differing, ct: otherPresets }, reading).allowed).toBe(false);
    expect(refused(() => read({ ...broken, ct: otherPresets }, reading))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
  });
});

describe("presets by name under a catalog that changed them (Section 8.1, 8.3)", () => {
  const later = defineCatalog({
    ...data,
    presets: { ...data.presets, viewer: ["chat:read"], player: ["match:join"] },
  });
  const roles: StoredRole[] = [{ name: "desk", entries: ["viewer", "-player", "report:list"] }];
  const statements: Statement[] = [
    { kind: "assign", subject: "lea", value: "desk", place: ACME },
    { kind: "assign", subject: "lea", value: "player", place: S1 },
    { kind: "assign", subject: "lea", value: "viewer", place: S1 },
    { kind: "exclude", subject: "lea", value: "chat:read", place: LOBBY },
  ];
  const grants = issueGrants(
    catalog,
    { subject: "lea", statements, roles },
    { omit: ["presets"], now },
  );

  it("are read from the catalog in force, as `ask` answers under it with the stored roles as issued", () => {
    for (const permission of later.data.permissions) {
      for (const place of ["/", ACME, `${ACME}/unit=u1`, S1, LOBBY]) {
        const carried = could(later, grants, { permission, place }, { now: () => THURSDAY * 1000 });
        const fresh = ask(
          later,
          { subject: "lea", statements, roles },
          { permission, place },
          { now: () => THURSDAY * 1000 },
        );
        expect([
          permission,
          place,
          carried.allowed,
          carried.by?.kind,
          carried.by?.value,
        ]).toStrictEqual([permission, place, fresh.allowed, fresh.by?.kind, fresh.by?.value]);
      }
    }
    expect(could(later, grants, { permission: "chat:read", place: S1 }, { now }).allowed).toBe(
      true,
    );
    expect(could(later, grants, { permission: "chat:send", place: S1 }, { now }).allowed).toBe(
      false,
    );
  });
});

describe("the size of what a read does not touch (Section 1, Section 8.3)", () => {
  const SIZE = 20000;
  const places = Array.from({ length: SIZE }, (_, index) => `/org=o${index}`);
  const huge = {
    ...lea,
    pl: [...lea.pl, ...places],
    nt: {
      ...lea.nt,
      ...Object.fromEntries(
        places.map((_, index) => [
          index % 2 ? `r${index}:*` : `role${index}`,
          { a: [[index + 2]] },
        ]),
      ),
    },
  };

  it("answers as without it, in a time that does not walk it", () => {
    const questions: Question[] = [
      send,
      { permission: "report:read", place: ACME },
      { permission: "match:join", place: S1 },
      { permission: "report:write", place: "/org=o7" },
    ];
    for (const question of questions)
      expect(read(huge, question)).toStrictEqual(read(lea, question));
    const rounds = 200;
    const start = performance.now();
    for (let round = 0; round < rounds; round++) read(huge, questions[round % questions.length]!);
    const perRead = (performance.now() - start) / rounds;
    expect(perRead).toBeLessThan(0.5);
  });
});
