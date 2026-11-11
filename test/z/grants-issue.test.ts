import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import { issueGrants } from "../../src/z/grants.ts";
import type { Statement, StoredRole } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

const MONDAY = 1794214800;
const FRIDAY = 1794528000;
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
  presets: { writer: ["report:write", "chat:send"], viewer: ["report:read"] },
  places: { "/": ["org", "server"], "org": ["area", "unit"], "area": ["archive"] },
  manager: "access:manage",
});

const flat = defineCatalog({
  permissions: ["post:read", "post:write"],
  presets: { viewer: ["post:read"], editor: ["post:read", "post:write"] },
  places: false,
});

function issue(
  statements: Statement[],
  options?: { subject?: string; groups?: string[]; bases?: string[]; roles?: StoredRole[] },
) {
  return issueGrants(catalog, options?.subject ?? "sue", {
    statements,
    groups: options?.groups,
    bases: options?.bases,
    roles: options?.roles,
    now: () => MONDAY * 1000,
  });
}

describe("the examples of the grants object", () => {
  it("writes Zoe's allow and her own exclusion at the organisation", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "zoe", value: "report:*", place: ACME },
        { kind: "exclude", subject: "zoe", value: "report:write", place: ACME },
      ],
      { subject: "zoe" },
    );
    expect(grants).toStrictEqual({
      v: "1",
      ct: catalog.fingerprint,
      at: MONDAY,
      pl: [ACME],
      nt: { "report:*": { a: [[0]] }, "report:write": { x: [[0]] } },
    });
  });

  it("writes Sue's team as bundle 1 and her own allow in no bundle", () => {
    const grants = issue(
      [
        { kind: "assign", subject: "team", value: "writer", place: ACME },
        { kind: "exclude", subject: "team", value: "report:write", place: ARCHIVES },
        { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
      ],
      { groups: ["team"] },
    );
    expect(grants).toStrictEqual({
      v: "1",
      ct: catalog.fingerprint,
      at: MONDAY,
      pl: [ACME, ARCHIVES],
      nt: {
        "report:write": { a: [[0, FRIDAY]], x: [[1, null, 1]] },
        "writer": { a: [[0, null, 1]] },
      },
    });
  });

  it("writes Ed's two presets with no place table in a flat application", () => {
    const grants = issueGrants(flat, "ed", {
      statements: [
        { kind: "assign", subject: "ed", value: "viewer" },
        { kind: "assign", subject: "ed", value: "editor", expiresAt: NEXT_MONDAY },
      ],
      now: () => MONDAY * 1000,
    });
    expect(grants).toStrictEqual({
      v: "1",
      ct: flat.fingerprint,
      at: MONDAY,
      nt: { editor: { a: [[null, NEXT_MONDAY]] }, viewer: { a: [[]] } },
    });
  });
});

describe("what is kept", () => {
  it("keeps only the live statements about the subject and its groups", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "sue", value: "chat:read" },
        { kind: "allow", subject: "sue", value: "chat:send", expiresAt: MONDAY },
        { kind: "allow", subject: "bob", value: "report:read" },
        { kind: "deny", subject: "staff", value: "match:join" },
        { kind: "deny", subject: "others", value: "chat:read" },
      ],
      { groups: ["staff"] },
    );
    expect(grants.nt).toStrictEqual({ "chat:read": { a: [[]] }, "match:join": { d: [[]] } });
  });

  it("keeps what sits above a base at its own place and what sits under it, nothing beside it", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "sue", value: "chat:read" },
        { kind: "deny", subject: "sue", value: "chat:send", place: ACME },
        { kind: "allow", subject: "sue", value: "report:read", place: `${ARCHIVES}/archive=2024` },
        { kind: "allow", subject: "sue", value: "report:write", place: "/org=acme/unit=u7" },
        { kind: "allow", subject: "sue", value: "match:join", place: "/org=globex" },
      ],
      { bases: [ARCHIVES] },
    );
    expect(grants.bs).toStrictEqual([ARCHIVES]);
    expect(grants.pl).toStrictEqual([ACME, `${ARCHIVES}/archive=2024`]);
    expect(grants.nt).toStrictEqual({
      "chat:read": { a: [[]] },
      "chat:send": { d: [[0]] },
      "report:read": { a: [[1]] },
    });
  });

  it("lists the bases once each, sorted, and drops a base that another covers", () => {
    const bases = ["/server=s1", ARCHIVES, ACME, "/server=s1"];
    expect(issue([], { bases }).bs).toStrictEqual([ACME, "/server=s1"]);
    expect(issue([], { bases: [ACME, "/"] }).bs).toBeUndefined();
    expect(issue([]).bs).toBeUndefined();
  });

  it("leaves out what gives, blocks and takes out nothing", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "sue", value: "invoice:read" },
        { kind: "deny", subject: "sue", value: "invoice:*" },
        { kind: "allow", subject: "sue", value: "chat:read", place: "/unit=u7" },
        { kind: "assign", subject: "sue", value: "ghost" },
        { kind: "assign", subject: "sue", value: "hollow" },
        { kind: "assign", subject: "sue", value: "local", place: "/org=globex" },
      ],
      {
        roles: [
          { name: "hollow", entries: ["chat:send", "-chat:send"] },
          { name: "local", home: ACME, entries: ["chat:read"] },
        ],
      },
    );
    expect(grants.nt).toStrictEqual({});
    expect(grants).not.toHaveProperty("pl");
    expect(grants).not.toHaveProperty("rl");
  });
});

describe("roles", () => {
  it("keeps a preset by name and a stored role as one row of what it resolved to", () => {
    const roles: StoredRole[] = [
      { name: "moderator", entries: ["chat:*", "-chat:read"] },
      { name: "sender", home: ACME, entries: ["chat:send"] },
    ];
    const grants = issue(
      [
        { kind: "assign", subject: "sue", value: "moderator", place: ACME },
        { kind: "assign", subject: "sue", value: "moderator", place: "/server=s1" },
        { kind: "assign", subject: "sue", value: "sender", place: ARCHIVES, expiresAt: FRIDAY },
        { kind: "assign", subject: "sue", value: "viewer" },
      ],
      { roles },
    );
    expect(grants.rl).toStrictEqual([["chat:send"]]);
    expect(grants.pl).toStrictEqual([ACME, ARCHIVES, "/server=s1"]);
    expect(grants.nt).toStrictEqual({
      "#0": { a: [[0], [1, FRIDAY], [2]] },
      "viewer": { a: [[]] },
    });
  });
});

describe("bundles", () => {
  const statements: Statement[] = [
    { kind: "assign", subject: "blue", value: "writer", place: ACME },
    { kind: "assign", subject: "red", value: "writer", place: ACME },
    { kind: "assign", subject: "green", value: "viewer", place: ACME },
    { kind: "exclude", subject: "red", value: "report:write", place: ARCHIVES },
    { kind: "exclude", subject: "blue", value: "chat:send", place: ACME },
    { kind: "deny", subject: "blue", value: "match:join" },
    { kind: "exclude", subject: "sue", value: "chat:read", place: ACME },
    { kind: "allow", subject: "sue", value: "chat:read", place: ARCHIVES },
  ];

  it("number each group with an exclusion, and only its values and exclusions", () => {
    const grants = issue(statements, { groups: ["red", "green", "blue"] });
    expect(grants.nt).toStrictEqual({
      "chat:read": { a: [[1]], x: [[0]] },
      "chat:send": { x: [[0, null, 1]] },
      "match:join": { d: [[]] },
      "report:write": { x: [[1, null, 2]] },
      "viewer": { a: [[0]] },
      "writer": {
        a: [
          [0, null, 1],
          [0, null, 2],
        ],
      },
    });
  });

  it("are left out with the exclusions that made them when the group's exclusion is not kept", () => {
    const grants = issue(statements, { groups: ["red"], bases: ["/org=acme/unit=u7"] });
    expect(grants.nt).toStrictEqual({ "chat:read": { x: [[0]] }, "writer": { a: [[0]] } });
  });
});

describe("a permanent manager", () => {
  it("carries no deny and no exclusion, from itself or its groups", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "ops", value: "*" },
        { kind: "deny", subject: "sue", value: "report:read", place: ACME },
        { kind: "exclude", subject: "ops", value: "*", place: ACME },
        { kind: "assign", subject: "ops", value: "writer", place: ACME },
      ],
      { groups: ["ops"] },
    );
    expect(grants.nt).toStrictEqual({ "*": { a: [[]] }, "writer": { a: [[0]] } });
  });

  it("is not made by a `*` with an end, which keeps the denies", () => {
    const grants = issue([
      { kind: "allow", subject: "sue", value: "*", expiresAt: FRIDAY },
      { kind: "deny", subject: "sue", value: "report:read" },
    ]);
    expect(grants.nt).toStrictEqual({ "*": { a: [[null, FRIDAY]] }, "report:read": { d: [[]] } });
  });
});

describe("stable output", () => {
  it("writes the same object, member for member, whatever order the statements come in", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "team", value: "writer", place: ACME },
      { kind: "exclude", subject: "team", value: "report:write", place: ARCHIVES },
      { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
      { kind: "allow", subject: "sue", value: "report:write", place: ARCHIVES },
      { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
      { kind: "allow", subject: "sue", value: "chat:*" },
    ];
    const one = JSON.stringify(issue(statements, { groups: ["team"] }));
    const two = JSON.stringify(issue(statements.toReversed(), { groups: ["team"] }));
    expect(two).toBe(one);
    expect(issue(statements, { groups: ["team"] }).nt["report:write"]?.a).toStrictEqual([
      [0, FRIDAY],
      [1],
    ]);
  });
});

describe("refusals", () => {
  it.each([
    ["an empty subject", () => issueGrants(catalog, "", { statements: [] }), "question"],
    [
      "groups that are not strings",
      () => issueGrants(catalog, "sue", { statements: [], groups: [1] as unknown as string[] }),
      "question",
    ],
    [
      "a base that is not canonical",
      () => issueGrants(catalog, "sue", { statements: [], bases: ["/org=a/"] }),
      "place",
    ],
    ["no base at all", () => issueGrants(catalog, "sue", { statements: [], bases: [] }), "place"],
    [
      "statements that are not a list",
      () => issueGrants(catalog, "sue", { statements: {} as unknown as Statement[] }),
      "statement",
    ],
  ])("refuses %s as malformed", (_, run, what) => {
    expect(refused(run)).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what } });
  });

  it("refuses a base outside the structure", () => {
    expect(
      refused(() => issueGrants(catalog, "sue", { statements: [], bases: ["/unit=u7"] })),
    ).toMatchObject({ code: "ERR_AUTHZ_PLACE_OUTSIDE", cause: { place: "/unit=u7" } });
  });
});
