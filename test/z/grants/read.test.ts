import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../../src/z/catalog.ts";
import { could, issueGrants } from "../../../src/z/grants.ts";
import type { Grants, Question, Statement } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

const DAY = 86400;
const MONDAY = 1794214800;
const THURSDAY = 1794441600;
const FRIDAY = 1794528000;
const SATURDAY = 1794614400;
const NEXT_MONDAY = 1794819600;
const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";

const catalog = defineCatalog({
  permissions: [
    "report:list",
    "report:read",
    "report:write",
    "chat:read",
    "chat:send",
    "match:join",
    "access:manage",
  ],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: {
    writer: ["report:write", "chat:send"],
    viewer: ["report:read"],
    player: ["chat:*", "match:join"],
  },
  places: {
    "/": ["org", "server"],
    "org": ["area", "unit"],
    "area": ["archive"],
    "server": ["channel"],
  },
});
const ct = catalog.fingerprint;
type P = (typeof catalog.data.permissions)[number];

function read(grants: unknown, question: Question<P>, at: number) {
  return could(catalog, grants, question, { now: () => at * 1000 });
}

function issue(statements: Statement[], options: { subject: string; bases?: string[] }) {
  const { subject, bases } = options;
  return issueGrants(catalog, { subject, statements }, { bases, now: () => MONDAY * 1000 });
}

const [, presetsSegment] = ct.split(".");
const otherPresets = `${ct.split(".")[0]}.AAAAAAAAAAA`;
const otherDeclares = `AAAAAAAAAAA.${presetsSegment}`;

const sue = {
  v: "1",
  ct,
  at: MONDAY,
  pl: [ACME, ARCHIVES],
  nt: {
    "report:write": { a: [[0, FRIDAY]], x: [[1, null, 1]] },
    "writer": { a: [[0, null, 1]] },
  },
};

describe("Sue in the archives", () => {
  const write = { permission: "report:write" } as const;

  it("writes on Thursday through her own allow, which the team's exclusion does not touch", () => {
    expect(read(sue, { ...write, place: ARCHIVES }, THURSDAY)).toStrictEqual({
      allowed: true,
      covered: true,
      by: { kind: "allow", value: "report:write", place: ACME, expiresAt: FRIDAY },
    });
  });

  it("is denied on Saturday, once her allow has ended, and nothing was issued again", () => {
    expect(read(sue, { ...write, place: ARCHIVES }, SATURDAY)).toStrictEqual({
      allowed: false,
      covered: true,
    });
  });

  it("still writes elsewhere in the organisation on Saturday, through the team's role", () => {
    const decision = read(sue, { ...write, place: `${ACME}/unit=u7` }, SATURDAY);
    expect(decision.by).toStrictEqual({ kind: "assign", value: "writer", place: ACME });
  });

  it("is denied on Thursday too when the exclusion is about Sue herself", () => {
    const own = { ...sue, nt: { ...sue.nt, "report:write": { a: [[0, FRIDAY]], x: [[1]] } } };
    expect(read(own, { ...write, place: ARCHIVES }, THURSDAY).allowed).toBe(false);
    expect(read(own, { ...write, place: ACME }, THURSDAY).allowed).toBe(true);
  });

  it("loses `report:read` in the archives on Saturday with the writing that gave it, and keeps sending", () => {
    expect(read(sue, { permission: "report:read", place: ARCHIVES }, SATURDAY).allowed).toBe(false);
    expect(read(sue, { permission: "report:read", place: ARCHIVES }, THURSDAY).allowed).toBe(true);
    expect(read(sue, { permission: "chat:send", place: ARCHIVES }, SATURDAY).allowed).toBe(true);
  });
});

describe("time passing", () => {
  const gil: Statement[] = [
    { kind: "assign", subject: "gil", value: "player", place: "/server=s1" },
    { kind: "deny", subject: "gil", value: "match:join", expiresAt: NEXT_MONDAY },
  ];
  const grants = issue(gil, { subject: "gil" });
  const join = { permission: "match:join", place: "/server=s1/channel=lobby" } as const;

  it("lifts a ban by itself: denied on Thursday, allowed the Tuesday after", () => {
    expect(read(grants, join, THURSDAY).by).toStrictEqual({
      kind: "deny",
      value: "match:join",
      place: "/",
      expiresAt: NEXT_MONDAY,
    });
    expect(read(grants, join, NEXT_MONDAY + DAY).allowed).toBe(true);
  });

  it("ends a statement at the very second of its end, for what gives and what blocks", () => {
    const ending = issue(
      [
        { kind: "allow", subject: "ann", value: "chat:read", expiresAt: FRIDAY },
        { kind: "allow", subject: "ann", value: "match:join" },
        { kind: "deny", subject: "ann", value: "match:join", expiresAt: FRIDAY },
      ],
      { subject: "ann" },
    );
    expect(read(ending, { permission: "chat:read" }, FRIDAY - 1).allowed).toBe(true);
    expect(read(ending, { permission: "chat:read" }, FRIDAY).allowed).toBe(false);
    expect(read(ending, { permission: "match:join" }, FRIDAY - 1).allowed).toBe(false);
    expect(read(ending, { permission: "match:join" }, FRIDAY).allowed).toBe(true);
  });

  it("keeps an exclusion to its place and under it: muted in the lobby, speaking in the help room", () => {
    const muted = issue(
      [
        ...gil,
        { kind: "exclude", subject: "gil", value: "chat:send", place: "/server=s1" },
        { kind: "allow", subject: "gil", value: "chat:send", place: "/server=s1/channel=help" },
      ],
      { subject: "gil" },
    );
    const send = (place: string) => read(muted, { permission: "chat:send", place }, THURSDAY);
    expect(send("/server=s1/channel=lobby").allowed).toBe(false);
    expect(send("/server=s1/channel=help").by).toStrictEqual({
      kind: "allow",
      value: "chat:send",
      place: "/server=s1/channel=help",
    });
    expect(
      read(muted, { permission: "chat:read", place: "/server=s1/channel=lobby" }, THURSDAY).allowed,
    ).toBe(true);
  });

  it("reads at the second of issue, and refuses a second before", () => {
    expect(read(grants, join, MONDAY).allowed).toBe(false);
    expect(refused(() => read(grants, join, MONDAY - 1))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_EARLY",
    });
  });
});

describe("bases", () => {
  const statements: Statement[] = [
    { kind: "deny", subject: "pat", value: "*" },
    { kind: "assign", subject: "marketing", value: "viewer", place: ACME },
  ];
  const drive = issue(statements, { subject: "pat", bases: [ACME] });

  it("answers not covered outside them, never denied, even under a deny carried from above", () => {
    const outside = { allowed: false, covered: false };
    expect(read(drive, { permission: "report:read", place: "/org=globex" }, MONDAY)).toStrictEqual(
      outside,
    );
    expect(read(drive, { permission: "report:read" }, MONDAY)).toStrictEqual(outside);
    expect(read(drive, { permission: "report:read", place: "/org=acme-x" }, MONDAY)).toStrictEqual(
      outside,
    );
    expect(read(drive, { permission: "report:read", place: ACME }, MONDAY)).toMatchObject({
      allowed: false,
      covered: true,
    });
  });

  it("reads several sets together: covered by any, allowed only when every covering one allows", () => {
    const people = [{ kind: "assign", subject: "mel", value: "viewer" }] satisfies Statement[];
    const platform = issue(people, { subject: "mel", bases: ["/server=s1"] });
    const older = issue([...people, { kind: "deny", subject: "mel", value: "report:read" }], {
      subject: "mel",
      bases: [ACME],
    });
    const newer = issue(people, { subject: "mel", bases: [ACME] });
    const ask = (sets: Grants[], place?: string) =>
      read(sets, { permission: "report:read", place }, MONDAY);
    expect(ask([platform, newer], "/server=s1/channel=c").allowed).toBe(true);
    expect(ask([platform, newer], ARCHIVES).allowed).toBe(true);
    expect(ask([platform, older, newer], ARCHIVES)).toMatchObject({
      allowed: false,
      covered: true,
      by: { kind: "deny" },
    });
    expect(ask([newer, older], ARCHIVES).allowed).toBe(false);
    expect(ask([platform, newer], "/org=globex").covered).toBe(false);
    expect(ask([], ACME)).toStrictEqual({ allowed: false, covered: false });
  });

  it("names what decided in the first covering set that does not allow, else in the first covering set", () => {
    const viewer = [{ kind: "assign", subject: "mel", value: "viewer" }] satisfies Statement[];
    const assigned = issue(viewer, { subject: "mel", bases: [ACME] });
    const allowing = issue([{ kind: "allow", subject: "mel", value: "report:read", place: ACME }], {
      subject: "mel",
      bases: [ARCHIVES],
    });
    const denying = issue([...viewer, { kind: "deny", subject: "mel", value: "report:read" }], {
      subject: "mel",
      bases: [ACME],
    });
    const empty = issue([], { subject: "mel", bases: [ACME] });
    const ask = (sets: Grants[]) =>
      read(sets, { permission: "report:read", place: ARCHIVES }, MONDAY);
    const assignment = { kind: "assign", value: "viewer", place: "/" };
    const allow = { kind: "allow", value: "report:read", place: ACME };
    const deny = { kind: "deny", value: "report:read", place: "/" };
    expect(ask([assigned, allowing])).toStrictEqual({
      allowed: true,
      covered: true,
      by: assignment,
    });
    expect(ask([allowing, assigned])).toStrictEqual({ allowed: true, covered: true, by: allow });
    expect(ask([allowing, denying])).toStrictEqual({ allowed: false, covered: true, by: deny });
    expect(ask([denying, empty])).toStrictEqual({ allowed: false, covered: true, by: deny });
    expect(ask([allowing, empty, denying])).toStrictEqual({ allowed: false, covered: true });
  });

  it("refuses the whole read when one set refuses, even one that does not cover the place", () => {
    const people = [{ kind: "assign", subject: "mel", value: "viewer" }] satisfies Statement[];
    const platform = issue(people, { subject: "mel", bases: ["/server=s1"] });
    const named = issueGrants(
      catalog,
      { subject: "mel", statements: people },
      { bases: [ACME], omit: ["presets"], now: () => MONDAY * 1000 },
    );
    const stale = { ...named, ct: otherPresets };
    expect(
      refused(() =>
        read([platform, stale], { permission: "report:read", place: "/server=s1" }, MONDAY),
      ),
    ).toMatchObject({ code: "ERR_AUTHZ_GRANTS_CATALOG" });
  });
});

describe("the question", () => {
  const grants = issue(
    [
      { kind: "assign", subject: "gil", value: "player" },
      { kind: "deny", subject: "gil", value: "chat:send", place: "/server=s1" },
    ],
    { subject: "gil" },
  );

  it("is refused as `ask` refuses it, whatever the grants hold", () => {
    for (const set of [grants, null, { ...grants, ct: "x" }]) {
      expect(refused(() => read(set, { permission: "chat:*" as P }, MONDAY))).toMatchObject({
        code: "ERR_AUTHZ_QUESTION_INVALID",
        cause: { reason: "wildcard" },
      });
      expect(refused(() => read(set, { permission: "invoice:read" as P }, MONDAY))).toMatchObject({
        code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
      });
      expect(
        refused(() => read(set, { permission: "chat:read", place: "/unit=u1" }, MONDAY)),
      ).toMatchObject({ code: "ERR_AUTHZ_PLACE_OUTSIDE" });
      expect(refused(() => read(set, { permission: "" as P }, MONDAY))).toMatchObject({
        code: "ERR_AUTHZ_QUESTION_INVALID",
        cause: { reason: "empty" },
      });
    }
  });
});

describe("a permanent allow of `*` at the root", () => {
  const owner = {
    v: "1",
    ct,
    at: MONDAY,
    pl: [ACME],
    nt: { "*": { a: [[]] }, "report:read": { d: [[0]] }, "chat:*": { x: [[0]] } },
  };

  it("is denied and excluded in grants issued before, as anyone is", () => {
    expect(read(owner, { permission: "report:write", place: ARCHIVES }, THURSDAY)).toStrictEqual({
      allowed: false,
      covered: true,
      by: { kind: "deny", value: "report:read", place: ACME },
    });
    expect(read(owner, { permission: "chat:send", place: ACME }, THURSDAY).allowed).toBe(false);
    expect(read(owner, { permission: "chat:send", place: "/server=s1" }, THURSDAY).allowed).toBe(
      true,
    );
  });

  it("is issued with its subject's denies and read the same way", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "owner", value: "*" },
        { kind: "deny", subject: "owner", value: "report:read", place: ACME },
      ],
      { subject: "owner" },
    );
    expect(read(grants, { permission: "report:list", place: ACME }, THURSDAY).allowed).toBe(true);
    expect(read(grants, { permission: "report:write", place: ACME }, THURSDAY).allowed).toBe(false);
  });
});

describe("grants written by hand", () => {
  it("read alike whatever the order of members, lists and items, with members of their own and items twice", () => {
    const text = `{
      "nt": {
        "writer": { "a": [[1, null, 7], [1, null, 7]] },
        "report:write": { "x": [[0, null, 7]], "a": [[1, ${FRIDAY}], [1, ${FRIDAY}]] }
      },
      "sub": "sue",
      "exp": ${SATURDAY},
      "pl": ["${ARCHIVES}", "${ACME}"],
      "at": ${MONDAY},
      "ct": "${ct}",
      "v": "1"
    }`;
    const grants: unknown = JSON.parse(text);
    for (const at of [THURSDAY, SATURDAY]) {
      for (const place of [ARCHIVES, ACME, `${ARCHIVES}/archive=2019`]) {
        for (const permission of ["report:write", "report:read", "chat:send"] as const) {
          expect(read(grants, { permission, place }, at)).toStrictEqual(
            read(sue, { permission, place }, at),
          );
        }
      }
    }
  });

  it("read a subset of the entries with the tables they index", () => {
    const sending = { ...sue, nt: { writer: sue.nt.writer } };
    expect(read(sending, { permission: "chat:send", place: ARCHIVES }, SATURDAY).allowed).toBe(
      true,
    );
    const writing = { ...sue, nt: { "report:write": sue.nt["report:write"] } };
    expect(read(writing, { permission: "report:write", place: ARCHIVES }, THURSDAY).allowed).toBe(
      true,
    );
    expect(read(writing, { permission: "chat:send", place: ARCHIVES }, THURSDAY).allowed).toBe(
      false,
    );
  });

  it("read a stored role by its name in `sr`, and name it so", () => {
    const grants = {
      v: "1",
      ct,
      at: MONDAY,
      pm: ["chat:read", "report:list"],
      sr: { desk: [0], lister: [1] },
      nt: { lister: { a: [[]] } },
    };
    expect(read(grants, { permission: "report:list" }, MONDAY).by).toStrictEqual({
      kind: "assign",
      value: "lister",
      place: "/",
    });
    expect(read(grants, { permission: "chat:read" }, MONDAY).allowed).toBe(false);
  });

  it("read definitions through the permission table whatever its order", () => {
    const roles = [
      { name: "lead", entries: ["report:write", "chat:read", "access:manage", "-chat:send"] },
      { name: "desk", entries: ["chat:send", "lead"] },
    ];
    const issued = issueGrants(
      catalog,
      {
        subject: "sue",
        statements: [
          { kind: "assign", subject: "sue", value: "lead", place: ACME },
          { kind: "assign", subject: "sue", value: "desk", place: ARCHIVES, expiresAt: FRIDAY },
          { kind: "allow", subject: "sue", value: "report:list", place: "/server=s1" },
          { kind: "allow", subject: "sue", value: "match:*", place: ACME },
          { kind: "deny", subject: "sue", value: "chat:send", place: ARCHIVES, expiresAt: FRIDAY },
          { kind: "exclude", subject: "sue", value: "chat:read", place: ARCHIVES },
        ],
        roles,
      },
      { now: () => MONDAY * 1000 },
    );
    expect(issued.pm).toStrictEqual([
      "access:manage",
      "chat:read",
      "chat:send",
      "report:list",
      "report:write",
    ]);
    expect(Object.keys(issued.nt).toSorted()).toStrictEqual([
      "1",
      "2",
      "3",
      "desk",
      "lead",
      "match:*",
    ]);
    const reversed = [...issued.pm!].toReversed();
    const moved = (position: number) => reversed.indexOf(issued.pm![position]!);
    const movedEntry = (entry: string | number) =>
      typeof entry === "number"
        ? moved(entry)
        : /^-[0-9]+$/.test(entry)
          ? `-${moved(Number(entry.slice(1)))}`
          : entry;
    const rewritten = {
      ...issued,
      pm: reversed,
      sr: Object.fromEntries(
        Object.entries(issued.sr!).map(([name, entries]) => [name, entries.map(movedEntry)]),
      ),
      nt: Object.fromEntries(
        Object.entries(issued.nt).map(([name, entry]) => [
          /^[0-9]+$/.test(name) ? String(moved(Number(name))) : name,
          entry,
        ]),
      ),
    };
    for (const permission of catalog.data.permissions) {
      for (const place of ["/", ACME, ARCHIVES, `${ARCHIVES}/archive=x`, "/server=s1"]) {
        for (const at of [MONDAY, THURSDAY, FRIDAY, SATURDAY]) {
          expect(read(rewritten, { permission, place }, at)).toStrictEqual(
            read(issued, { permission, place }, at),
          );
        }
      }
    }
    expect(read(rewritten, { permission: "report:write", place: ARCHIVES }, SATURDAY).allowed).toBe(
      true,
    );
    expect(read(rewritten, { permission: "chat:send", place: ACME }, THURSDAY).allowed).toBe(false);
    expect(
      read(rewritten, { permission: "chat:send", place: ARCHIVES }, THURSDAY).by,
    ).toStrictEqual({ kind: "deny", value: "chat:send", place: ARCHIVES, expiresAt: FRIDAY });
  });

  it("read a permission named by its position, and name it by its name", () => {
    const grants = {
      v: "1",
      ct,
      at: MONDAY,
      pl: [ACME],
      pm: ["chat:read", "report:list", "report:write"],
      sr: { desk: [0] },
      nt: { "desk": { a: [[]] }, "0": { x: [[0]] }, "1": { d: [[0]] }, "2": { a: [[]] } },
    };
    expect(read(grants, { permission: "report:write" }, MONDAY).by).toStrictEqual({
      kind: "allow",
      value: "report:write",
      place: "/",
    });
    expect(read(grants, { permission: "report:write", place: ACME }, MONDAY).by).toStrictEqual({
      kind: "deny",
      value: "report:list",
      place: ACME,
    });
    expect(read(grants, { permission: "chat:read", place: ACME }, MONDAY)).toStrictEqual({
      allowed: false,
      covered: true,
    });
    expect(read(grants, { permission: "chat:read" }, MONDAY).by).toStrictEqual({
      kind: "assign",
      value: "desk",
      place: "/",
    });
  });

  it("read a definition that repeats an entry as if written once", () => {
    const grants = { v: "1", ct, at: MONDAY, pm: ["chat:read"], sr: { desk: [0, 0] } };
    expect(
      read({ ...grants, nt: { desk: { a: [[]] } } }, { permission: "chat:read" }, MONDAY),
    ).toMatchObject({ allowed: true });
  });

  it("read a permission table nothing points at, beside an empty definition", () => {
    const tableOnly = {
      v: "1",
      ct,
      at: MONDAY,
      pm: ["chat:read", "report:write"],
      sr: { none: [] },
      nt: {},
    };
    expect(read(tableOnly, { permission: "chat:read" }, MONDAY).allowed).toBe(false);
    const subset = { ...tableOnly, nt: { "1": { a: [[]] }, "none": { a: [[]] } } };
    expect(read(subset, { permission: "report:write" }, MONDAY).by).toStrictEqual({
      kind: "allow",
      value: "report:write",
      place: "/",
    });
  });

  it("ignore `rl`, a member this revision does not define", () => {
    const withRl = {
      v: "1",
      ct,
      at: MONDAY,
      rl: [["chat:read"]],
      nt: { "chat:read": { a: [[]] } },
    };
    expect(read(withRl, { permission: "chat:read" }, MONDAY).allowed).toBe(true);
  });

  it("are refused with an own `__proto__` entry instead of reading through it", () => {
    const grants: unknown = JSON.parse(
      `{"v":"1","ct":"${ct}","at":${MONDAY},"nt":{"__proto__":{"a":[[]]}}}`,
    );
    expect(refused(() => read(grants, { permission: "chat:read" }, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
  });
});

describe("roles, resolved at read from the definitions the grants hold", () => {
  const at = { v: "1", at: MONDAY } as const;

  it("read a copy of a preset whatever the catalog's preset of that name gives", () => {
    const grants = {
      ...at,
      ct,
      pm: ["match:join"],
      ps: { viewer: [0] },
      nt: { viewer: { a: [[]] } },
    };
    expect(read(grants, { permission: "match:join" }, MONDAY)).toStrictEqual({
      allowed: true,
      covered: true,
      by: { kind: "assign", value: "viewer", place: "/" },
    });
    expect(read(grants, { permission: "report:read" }, MONDAY).allowed).toBe(false);
  });

  it("read a name in no table as the catalog's preset where the grants hold no copies", () => {
    const named = {
      ...at,
      ct,
      pm: ["report:list"],
      sr: { desk: ["viewer", "-0"] },
      nt: { desk: { a: [[]] }, viewer: { a: [[0]] } },
      pl: [ACME],
    };
    expect(read(named, { permission: "report:read" }, MONDAY).allowed).toBe(false);
    expect(read(named, { permission: "report:read", place: ACME }, MONDAY).by).toStrictEqual({
      kind: "assign",
      value: "viewer",
      place: ACME,
    });
  });

  it("read a name in no table as a role that does not exist where the grants hold copies", () => {
    const copies = {
      ...at,
      ct,
      ps: { player: ["chat:*"] },
      sr: { desk: ["viewer"], mixed: ["player", "-viewer"] },
      nt: { desk: { a: [[]] }, viewer: { a: [[]] }, mixed: { a: [[]] }, player: { a: [[]] } },
    };
    expect(read(copies, { permission: "report:read" }, MONDAY).allowed).toBe(false);
    expect(read(copies, { permission: "chat:send" }, MONDAY).by).toStrictEqual({
      kind: "assign",
      value: "player",
      place: "/",
    });
    const alone = { ...copies, nt: { mixed: { a: [[]] } } };
    expect(read(alone, { permission: "chat:send" }, MONDAY).allowed).toBe(false);
  });

  it("read a name in `sr` as that stored role, even where the catalog declares a preset of it", () => {
    const grants = {
      ...at,
      ct,
      pm: ["access:manage"],
      sr: { viewer: [0] },
      nt: { viewer: { a: [[]] } },
    };
    expect(read(grants, { permission: "access:manage" }, MONDAY).allowed).toBe(true);
    expect(read(grants, { permission: "report:read" }, MONDAY).allowed).toBe(false);
  });

  it("give nothing for a role on a cycle, nor for a role that names it with or without `-`", () => {
    const grants = {
      ...at,
      ct,
      pm: ["chat:read", "chat:send"],
      sr: {
        looped: [0, "other"],
        other: ["looped"],
        wide: [1, "-looped"],
        narrow: [1, "looped"],
        fine: [1],
      },
      nt: { looped: { a: [[]] }, wide: { a: [[]] }, narrow: { a: [[]] } },
    };
    expect(read(grants, { permission: "chat:read" }, MONDAY).allowed).toBe(false);
    expect(read(grants, { permission: "chat:send" }, MONDAY).allowed).toBe(false);
    const fine = { ...grants, nt: { ...grants.nt, fine: { a: [[]] } } };
    expect(read(fine, { permission: "chat:send" }, MONDAY).by).toMatchObject({ value: "fine" });
  });

  it("read an unknown permission in a definition as inert and the rest as written", () => {
    const grants = {
      ...at,
      ct,
      pm: ["chat:send", "invoice:read"],
      sr: { desk: [0, 1, "-1", "invoice:*", "-invoice:*"] },
      nt: { desk: { a: [[]] } },
    };
    expect(read(grants, { permission: "chat:send" }, MONDAY).by).toMatchObject({ value: "desk" });
  });

  it("read a stored role that excludes a preset copied beside it", () => {
    const grants = issueGrants(
      catalog,
      {
        subject: "kim",
        statements: [{ kind: "assign", subject: "kim", value: "desk", place: ACME }],
        roles: [{ name: "desk", entries: ["player", "report:write", "-viewer"] }],
      },
      { now: () => MONDAY * 1000 },
    );
    expect(grants.ps).toStrictEqual({ player: ["chat:*", 0], viewer: [1] });
    expect(read(grants, { permission: "report:write", place: ACME }, MONDAY).allowed).toBe(false);
    expect(read(grants, { permission: "match:join", place: ACME }, MONDAY).by).toStrictEqual({
      kind: "assign",
      value: "desk",
      place: ACME,
    });
  });
});

describe("grants issued under another catalog", () => {
  const named = issueGrants(
    catalog,
    { subject: "gil", statements: [{ kind: "assign", subject: "gil", value: "player" }] },
    { omit: ["presets"], now: () => MONDAY * 1000 },
  );

  it("are refused, naming the presets segment, when they name a preset they hold no copy of", () => {
    expect(
      refused(() => read({ ...named, ct: otherPresets }, { permission: "chat:read" }, MONDAY)),
    ).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_CATALOG",
      cause: { segment: "presets" },
    });
  });

  it("are refused for a preset named only inside a stored role's definition, with or without `-`", () => {
    for (const entry of ["player", "-player"]) {
      const grants = {
        v: "1",
        ct: otherPresets,
        at: MONDAY,
        pm: ["chat:read"],
        sr: { desk: [0, entry] },
        nt: { "0": { a: [[]] } },
      };
      expect(refused(() => read(grants, { permission: "chat:read" }, MONDAY))).toMatchObject({
        code: "ERR_AUTHZ_GRANTS_CATALOG",
        cause: { segment: "presets" },
      });
    }
  });

  it("are read when only the first segment differs, or when they name no preset by name", () => {
    expect(read({ ...named, ct: otherDeclares }, { permission: "chat:read" }, MONDAY).allowed).toBe(
      true,
    );
    const plain = { v: "1", ct: otherPresets, at: MONDAY, nt: { "chat:read": { a: [[]] } } };
    expect(read(plain, { permission: "chat:read" }, MONDAY).allowed).toBe(true);
    const copies = issue([{ kind: "assign", subject: "gil", value: "player" }], { subject: "gil" });
    expect(read({ ...copies, ct: otherPresets }, { permission: "chat:read" }, MONDAY).allowed).toBe(
      true,
    );
  });

  it("refuse another format and malformed grants before another catalog, and another catalog before the time of issue", () => {
    expect(
      refused(() =>
        read({ ...named, v: "2", ct: otherPresets }, { permission: "chat:read" }, MONDAY),
      ).code,
    ).toBe("ERR_AUTHZ_GRANTS_FORMAT");
    expect(
      refused(() =>
        read({ ...named, ct: otherPresets, nt: [] }, { permission: "chat:read" }, MONDAY),
      ).code,
    ).toBe("ERR_AUTHZ_MALFORMED");
    expect(
      refused(() => read({ ...named, ct: otherPresets }, { permission: "chat:read" }, MONDAY - 1))
        .code,
    ).toBe("ERR_AUTHZ_GRANTS_CATALOG");
  });
});

describe("refusals", () => {
  const plain = { v: "1", ct, at: MONDAY, pl: [ACME], nt: {} };
  const valid = { ...plain, pm: ["chat:read"], sr: { desk: [0] } };
  const ask = { permission: "chat:read" } as const;
  const malformed: [string, unknown][] = [
    ["a string", "grants"],
    ["null", null],
    ["a list inside a list", [[valid]]],
    ["no `v`", { ...valid, v: undefined }],
    ["a numeric `v`", { ...valid, v: 1 }],
    ["no `ct`", { ...valid, ct: undefined }],
    ["a numeric `ct`", { ...valid, ct: 9 }],
    ["a `ct` of one segment", { ...valid, ct: ct.split(".")[0] }],
    ["a `ct` of three segments", { ...valid, ct: `${ct}.${presetsSegment}` }],
    ["a `ct` of the former 43 characters", { ...valid, ct: "x".repeat(43) }],
    ["a `ct` with a segment of 12 characters", { ...valid, ct: `${ct}A` }],
    ["a `ct` outside the URL-safe alphabet", { ...valid, ct: `${ct.slice(0, 22)}+` }],
    ["no `at`", { ...valid, at: undefined }],
    ["`at` in milliseconds", { ...valid, at: MONDAY * 1000 }],
    ["a fractional `at`", { ...valid, at: MONDAY + 0.5 }],
    ["`at` as text", { ...valid, at: String(MONDAY) }],
    ["no `nt`", { ...valid, nt: undefined }],
    ["`nt` as a list", { ...valid, nt: [] }],
    ["`bs` that is not a list", { ...valid, bs: ACME }],
    ["a base that is not canonical", { ...valid, bs: ["/org=acme/"] }],
    ["`pl` holding the root", { ...valid, pl: ["/"] }],
    ["`pl` holding a key in lowercase hex", { ...valid, pl: ["/org=caf%c3%a9"] }],
    ["`pm` that is not a list", { ...valid, pm: {} }],
    ["a permission twice in `pm`", { ...valid, pm: ["chat:read", "chat:read"] }],
    ["a pattern in `pm`", { ...valid, pm: ["chat:*"] }],
    ["a permission not in its form in `pm`", { ...valid, pm: ["Chat:Read"] }],
    ["a position in `pm`", { ...valid, pm: [0] }],
    ["`sr` that is a list", { ...valid, sr: [[0]] }],
    ["`ps` that is a list", { ...valid, ps: [[0]] }],
    ["a definition that is not a list", { ...valid, sr: { desk: 0 } }],
    ["a role name that is not a token", { ...valid, sr: { Desk: [0] } }],
    [
      "an own `__proto__` definition",
      JSON.parse(`{"v":"1","ct":"${ct}","at":${MONDAY},"ps":{"__proto__":[]},"nt":{}}`),
    ],
    ["a name in both `ps` and `sr`", { ...valid, ps: { desk: [] } }],
    ["a permission by name in a definition", { ...valid, sr: { desk: ["chat:read"] } }],
    ["an excluded permission by name in a definition", { ...valid, sr: { desk: ["-chat:read"] } }],
    ["a position past the table", { ...valid, sr: { desk: [1] } }],
    ["an excluded position past the table", { ...valid, sr: { desk: ["-1"] } }],
    ["a negative position", { ...valid, sr: { desk: [-1] } }],
    ["a fractional position", { ...valid, sr: { desk: [0.5] } }],
    ["a position as text", { ...valid, sr: { desk: ["0"] } }],
    ["an excluded position with a leading zero", { ...valid, sr: { desk: ["-00"] } }],
    ["an entry excluded twice", { ...valid, sr: { desk: ["--0"] } }],
    ["`*:*` in a definition", { ...valid, sr: { desk: ["*:*"] } }],
    ["a position in a definition without `pm`", { ...valid, pm: undefined }],
    ["`*:*`", { ...valid, nt: { "*:*": { a: [[]] } } }],
    ["a name of the former `#` rows", { ...valid, nt: { "#0": { a: [[]] } } }],
    ["a name out of its form", { ...plain, nt: { "Chat:Read": { a: [[]] } } }],
    ["an entry that is not an object", { ...plain, nt: { "chat:read": [[]] } }],
    ["an entry with another member", { ...plain, nt: { "chat:read": { a: [], y: [] } } }],
    ["a deny under a role", { ...valid, nt: { viewer: { d: [[]] } } }],
    ["an exclusion under a stored role", { ...valid, nt: { desk: { x: [[]] } } }],
    ["items that are not a list", { ...plain, nt: { "chat:read": { a: {} } } }],
    ["an item that is not a list", { ...plain, nt: { "chat:read": { a: [0] } } }],
    ["an item of four elements", { ...plain, nt: { "chat:read": { a: [[0, null, 1, 2]] } } }],
    ["a place index past the table", { ...plain, nt: { "chat:read": { a: [[1]] } } }],
    ["a negative place index", { ...plain, nt: { "chat:read": { a: [[-1]] } } }],
    ["a fractional place index", { ...plain, nt: { "chat:read": { a: [[0.5]] } } }],
    ["a place written as a key", { ...plain, nt: { "chat:read": { a: [[ACME]] } } }],
    ["an end in milliseconds", { ...plain, nt: { "chat:read": { a: [[null, FRIDAY * 1000]] } } }],
    ["a negative end", { ...plain, nt: { "chat:read": { a: [[null, -1]] } } }],
    ["bundle zero", { ...plain, nt: { "chat:read": { a: [[null, null, 0]] } } }],
    ["a fractional bundle", { ...plain, nt: { "chat:read": { x: [[null, null, 1.5]] } } }],
    [
      "a bundle past the largest time",
      { ...plain, nt: { "chat:read": { a: [[null, null, 253402300800]] } } },
    ],
    ["a deny with a bundle", { ...plain, nt: { "chat:read": { d: [[null, null, 1]] } } }],
    ["a permission by name beside `pm`", { ...valid, nt: { "chat:read": { a: [[]] } } }],
    [
      "an unknown permission by name beside `pm`",
      { ...valid, nt: { "invoice:read": { a: [[]] } } },
    ],
    ["a position without `pm`", { ...plain, nt: { "0": { a: [[]] } } }],
    ["a position past `pm`", { ...valid, nt: { "1": { a: [[]] } } }],
    ["a position in an empty `pm`", { ...valid, pm: [], sr: {}, nt: { "0": { a: [[]] } } }],
    ["a position with a leading zero", { ...valid, nt: { "00": { a: [[]] } } }],
    ["a negative position as a name", { ...valid, nt: { "-1": { a: [[]] } } }],
    ["a fractional position as a name", { ...valid, nt: { "0.5": { a: [[]] } } }],
    ["a place index past the table under a position", { ...valid, nt: { "0": { a: [[1]] } } }],
    ["a deny with a bundle under a position", { ...valid, nt: { "0": { d: [[null, null, 1]] } } }],
  ];

  it.each(malformed)("refuses %s as malformed", (_, grants) => {
    expect(refused(() => read(grants, ask, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
  });

  it("accepts the largest bundle and the largest end", () => {
    const grants = { ...plain, nt: { "chat:read": { a: [[null, 253402300799, 253402300799]] } } };
    expect(read(grants, ask, MONDAY).allowed).toBe(true);
  });

  it("reads as inert what only the catalog does not know, never as malformed", () => {
    const inert = {
      ...plain,
      bs: ["/", "/unit=u1"],
      pl: [ACME, "/unit=u1", "/server=s1/area=a"],
      pm: ["chat:read", "invoice:read"],
      sr: { desk: [1, "invoice:*", "ghost", "-ghost"] },
      nt: {
        "0": { a: [[1], [2]] },
        "1": { a: [[]], d: [[]] },
        "invoice:*": { d: [[]] },
        "*:approve": { d: [[]] },
        "ghost": { a: [[]] },
        "desk": { a: [[]] },
      },
    };
    expect(read(inert, ask, MONDAY)).toStrictEqual({ allowed: false, covered: true });
    expect(
      read({ ...inert, nt: { ...inert.nt, "0": { a: [[0]] } } }, { ...ask, place: ACME }, MONDAY)
        .allowed,
    ).toBe(true);
  });

  it("covers nothing with a base that does not fit the structure", () => {
    const grants = { ...plain, bs: ["/unit=u1"], nt: { "*": { a: [[]] } } };
    expect(read(grants, ask, MONDAY)).toStrictEqual({ allowed: false, covered: false });
  });

  it("refuses another format revision before anything else it holds", () => {
    expect(refused(() => read({ v: "2" }, ask, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FORMAT",
    });
  });

  it("refuses a read before issue, once the members are checked", () => {
    expect(refused(() => read(valid, ask, MONDAY - 1))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_EARLY",
    });
    expect(refused(() => read({ ...valid, nt: [] }, ask, MONDAY - 1))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
  });
});
