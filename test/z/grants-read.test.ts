import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import { can, issueGrants, readGrants } from "../../src/z/grants.ts";
import type { Grants, GrantsQuestion, Statement } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

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
  manager: "access:manage",
});
const ct = catalog.fingerprint;
type P = (typeof catalog.data.permissions)[number];

function read(grants: unknown, question: GrantsQuestion<P>, at: number) {
  return readGrants(catalog, grants, question, { now: () => at * 1000 });
}

function issue(
  statements: Statement[],
  options: { subject: string; groups?: string[]; bases?: string[] },
) {
  return issueGrants(catalog, options.subject, {
    statements,
    groups: options.groups,
    bases: options.bases,
    now: () => MONDAY * 1000,
  });
}

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
  const drive = issue(statements, { subject: "pat", groups: ["marketing"], bases: [ACME] });

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
    const stale = { ...issue(people, { subject: "mel", bases: [ACME] }), ct: "another" };
    expect(
      refused(() =>
        read([platform, stale], { permission: "report:read", place: "/server=s1" }, MONDAY),
      ),
    ).toMatchObject({ code: "ERR_AUTHZ_GRANTS_CATALOG" });
  });
});

describe("the question and `can`", () => {
  const grants = issue(
    [
      { kind: "assign", subject: "gil", value: "player" },
      { kind: "deny", subject: "gil", value: "chat:send", place: "/server=s1" },
    ],
    { subject: "gil" },
  );
  const place = "/server=s1";

  it("answers `can` as one boolean, false where not covered", () => {
    const at = () => MONDAY * 1000;
    expect(can(catalog, grants, "match:join", { place, now: at })).toBe(true);
    expect(can(catalog, grants, "chat:send", { place, now: at })).toBe(false);
    expect(can(catalog, grants, "chat:read", { place, now: at })).toBe(true);
    const narrow = issue([{ kind: "allow", subject: "gil", value: "*" }], {
      subject: "gil",
      bases: [ACME],
    });
    expect(can(catalog, narrow, "match:join", { place, now: at })).toBe(false);
  });

  it("refuses a question as `decide` does", () => {
    expect(refused(() => read(grants, { permission: "chat:*" as P }, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_QUESTION_INVALID",
      cause: { reason: "wildcard" },
    });
    expect(refused(() => read(grants, { permission: "invoice:read" as P }, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
    });
    expect(
      refused(() => read(grants, { permission: "chat:read", place: "/unit=u1" }, MONDAY)),
    ).toMatchObject({ code: "ERR_AUTHZ_PLACE_OUTSIDE" });
    expect(refused(() => read(grants, { permission: "" as P }, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_QUESTION_INVALID",
      cause: { reason: "empty" },
    });
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

  it("read a row of stored permissions named by its index, and name it so", () => {
    const grants = {
      v: "1",
      ct,
      at: MONDAY,
      rl: [["chat:read"], ["report:list"]],
      nt: { "#1": { a: [[]] } },
    };
    expect(read(grants, { permission: "report:list" }, MONDAY).by).toStrictEqual({
      kind: "assign",
      value: "#1",
      place: "/",
    });
    expect(read(grants, { permission: "chat:read" }, MONDAY).allowed).toBe(false);
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

describe("refusals", () => {
  const valid = { v: "1", ct, at: MONDAY, pl: [ACME], rl: [["chat:read"]], nt: {} };
  const ask = { permission: "chat:read" } as const;
  const malformed: [string, unknown][] = [
    ["a string", "grants"],
    ["null", null],
    ["a list inside a list", [[valid]]],
    ["no `v`", { ...valid, v: undefined }],
    ["a numeric `v`", { ...valid, v: 1 }],
    ["no `ct`", { ...valid, ct: undefined }],
    ["a numeric `ct`", { ...valid, ct: 9 }],
    ["no `at`", { ...valid, at: undefined }],
    ["`at` in milliseconds", { ...valid, at: MONDAY * 1000 }],
    ["a fractional `at`", { ...valid, at: MONDAY + 0.5 }],
    ["`at` as text", { ...valid, at: String(MONDAY) }],
    ["no `nt`", { ...valid, nt: undefined }],
    ["`nt` as a list", { ...valid, nt: [] }],
    ["`bs` that is not a list", { ...valid, bs: ACME }],
    ["a base that is not canonical", { ...valid, bs: ["/org=acme/"] }],
    ["a base outside the structure", { ...valid, bs: ["/unit=u1"] }],
    ["`pl` holding the root", { ...valid, pl: ["/"] }],
    ["`pl` holding a key in lowercase hex", { ...valid, pl: ["/org=caf%c3%a9"] }],
    ["`pl` holding a place outside the structure", { ...valid, pl: ["/server=s1/area=a"] }],
    ["`rl` that is not a list", { ...valid, rl: {} }],
    ["a row that is not a list", { ...valid, rl: ["chat:read"] }],
    ["a row with an unknown permission", { ...valid, rl: [["invoice:read"]] }],
    ["a row with a pattern", { ...valid, rl: [["chat:*"]] }],
    ["an unknown permission", { ...valid, nt: { "invoice:read": { a: [[]] } } }],
    ["a pattern matching nothing", { ...valid, nt: { "invoice:*": { a: [[]] } } }],
    ["`*:*`", { ...valid, nt: { "*:*": { a: [[]] } } }],
    ["an unknown role", { ...valid, nt: { ghost: { a: [[]] } } }],
    ["a row that does not exist", { ...valid, nt: { "#1": { a: [[]] } } }],
    ["a row index with a leading zero", { ...valid, nt: { "#00": { a: [[]] } } }],
    ["a row without `rl`", { ...valid, rl: undefined, nt: { "#0": { a: [[]] } } }],
    ["an entry that is not an object", { ...valid, nt: { "chat:read": [[]] } }],
    ["an entry with another member", { ...valid, nt: { "chat:read": { a: [], y: [] } } }],
    ["a deny under a preset", { ...valid, nt: { viewer: { d: [[]] } } }],
    ["an exclusion under a row", { ...valid, nt: { "#0": { x: [[]] } } }],
    ["items that are not a list", { ...valid, nt: { "chat:read": { a: {} } } }],
    ["an item that is not a list", { ...valid, nt: { "chat:read": { a: [0] } } }],
    ["an item of four elements", { ...valid, nt: { "chat:read": { a: [[0, null, 1, 2]] } } }],
    ["a place index past the table", { ...valid, nt: { "chat:read": { a: [[1]] } } }],
    ["a negative place index", { ...valid, nt: { "chat:read": { a: [[-1]] } } }],
    ["a fractional place index", { ...valid, nt: { "chat:read": { a: [[0.5]] } } }],
    ["a place written as a key", { ...valid, nt: { "chat:read": { a: [[ACME]] } } }],
    ["an end in milliseconds", { ...valid, nt: { "chat:read": { a: [[null, FRIDAY * 1000]] } } }],
    ["a negative end", { ...valid, nt: { "chat:read": { a: [[null, -1]] } } }],
    ["bundle zero", { ...valid, nt: { "chat:read": { a: [[null, null, 0]] } } }],
    ["a fractional bundle", { ...valid, nt: { "chat:read": { x: [[null, null, 1.5]] } } }],
    [
      "a bundle past the largest time",
      { ...valid, nt: { "chat:read": { a: [[null, null, 253402300800]] } } },
    ],
    ["a deny with a bundle", { ...valid, nt: { "chat:read": { d: [[null, null, 1]] } } }],
  ];

  it.each(malformed)("refuses %s as malformed", (_, grants) => {
    expect(refused(() => read(grants, ask, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
  });

  it("accepts the largest bundle and the largest end", () => {
    const grants = { ...valid, nt: { "chat:read": { a: [[null, 253402300799, 253402300799]] } } };
    expect(read(grants, ask, MONDAY).allowed).toBe(true);
  });

  it("refuses another format revision before anything else it holds", () => {
    expect(refused(() => read({ v: "2" }, ask, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FORMAT",
    });
  });

  it("refuses another catalog before checking the members", () => {
    expect(refused(() => read({ ...valid, ct: "x", nt: [] }, ask, MONDAY))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_CATALOG",
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
