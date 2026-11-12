import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../../src/z/catalog.ts";
import { issueGrants } from "../../../src/z/grants.ts";
import type { Statement, StoredRole, SubjectStatements } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

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
});

const flat = defineCatalog({
  permissions: ["post:read", "post:write"],
  presets: { viewer: ["post:read"], editor: ["post:read", "post:write"] },
  places: false,
});

function issue(
  statements: Statement[],
  options?: { subject?: string; bases?: string[]; roles?: StoredRole[] },
) {
  const read = { subject: options?.subject ?? "sue", statements, roles: options?.roles };
  return issueGrants(catalog, read, { bases: options?.bases, now: () => MONDAY * 1000 });
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
    const grants = issue([
      { kind: "assign", subject: "team", value: "writer", place: ACME },
      { kind: "exclude", subject: "team", value: "report:write", place: ARCHIVES },
      { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
    ]);
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
    const statements: Statement[] = [
      { kind: "assign", subject: "ed", value: "viewer" },
      { kind: "assign", subject: "ed", value: "editor", expiresAt: NEXT_MONDAY },
    ];
    const grants = issueGrants(flat, { subject: "ed", statements }, { now: () => MONDAY * 1000 });
    expect(grants).toStrictEqual({
      v: "1",
      ct: flat.fingerprint,
      at: MONDAY,
      nt: { editor: { a: [[null, NEXT_MONDAY]] }, viewer: { a: [[]] } },
    });
  });
});

describe("what is kept", () => {
  it("keeps every live statement handed in, the subject's and its groups'", () => {
    const grants = issue([
      { kind: "allow", subject: "sue", value: "chat:read" },
      { kind: "allow", subject: "sue", value: "chat:send", expiresAt: MONDAY },
      { kind: "deny", subject: "staff", value: "match:join" },
      { kind: "allow", subject: "bob", value: "report:read" },
    ]);
    expect(grants.nt).toStrictEqual({
      "chat:read": { a: [[]] },
      "match:join": { d: [[]] },
      "report:read": { a: [[]] },
    });
  });

  it("bundles what another identifier gave as a group's, by the statements' subject alone", () => {
    const grants = issue([
      { kind: "assign", subject: "bob", value: "writer", place: ACME },
      { kind: "exclude", subject: "bob", value: "report:write", place: ARCHIVES },
      { kind: "exclude", subject: "sue", value: "chat:send", place: ARCHIVES },
    ]);
    expect(grants.nt).toStrictEqual({
      "chat:send": { x: [[1]] },
      "report:write": { x: [[1, null, 1]] },
      "writer": { a: [[0, null, 1]] },
    });
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
        { kind: "assign", subject: "sue", value: "looped", place: "/org=globex" },
        { kind: "assign", subject: "sue", value: "above", place: "/org=globex" },
      ],
      {
        roles: [
          { name: "hollow", entries: ["chat:send", "-chat:send"] },
          { name: "looped", entries: ["chat:read", "-other"] },
          { name: "other", entries: ["looped"] },
          { name: "above", entries: ["report:read", "looped"] },
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
      { name: "sender", entries: ["chat:send"] },
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
    const grants = issue(statements);
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
    const red = statements.filter(({ subject }) => subject === "red" || subject === "sue");
    const grants = issue(red, { bases: ["/org=acme/unit=u7"] });
    expect(grants.nt).toStrictEqual({ "chat:read": { x: [[0]] }, "writer": { a: [[0]] } });
  });
});

describe("a permanent allow of `*` at the root", () => {
  it("carries its subject's denies and exclusions, and its groups', like any other", () => {
    const grants = issue([
      { kind: "allow", subject: "ops", value: "*" },
      { kind: "deny", subject: "sue", value: "report:read", place: ACME },
      { kind: "exclude", subject: "ops", value: "chat:*", place: ACME },
      { kind: "assign", subject: "ops", value: "writer", place: ACME },
    ]);
    expect(grants.nt).toStrictEqual({
      "*": { a: [[null, null, 1]] },
      "chat:*": { x: [[0, null, 1]] },
      "report:read": { d: [[0]] },
      "writer": { a: [[0, null, 1]] },
    });
  });
});

describe("stored roles handed in", () => {
  it("keep a preset by name when a stored role has the same name", () => {
    const grants = issue([{ kind: "assign", subject: "sue", value: "viewer" }], {
      roles: [{ name: "viewer", entries: ["chat:send"] }],
    });
    expect(grants.nt).toStrictEqual({ viewer: { a: [[]] } });
    expect(grants).not.toHaveProperty("rl");
  });

  it("refuse two roles of one name", () => {
    const roles: StoredRole[] = [
      { name: "desk", entries: ["chat:read"] },
      { name: "desk", entries: ["chat:read"] },
    ];
    expect(
      refused(() => issue([{ kind: "assign", subject: "sue", value: "viewer" }], { roles })),
    ).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "desk", reason: "duplicate" },
    });
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
    const one = JSON.stringify(issue(statements));
    const two = JSON.stringify(issue(statements.toReversed()));
    expect(two).toBe(one);
    expect(issue(statements).nt["report:write"]?.a).toStrictEqual([[0, FRIDAY], [1]]);
  });
});

describe("refusals", () => {
  const sue = { subject: "sue", statements: [] };
  it.each([
    ["no read", () => issueGrants(catalog, null as unknown as SubjectStatements), "statement"],
    ["an empty subject", () => issueGrants(catalog, { subject: "", statements: [] }), "subject"],
    [
      "a base that is not canonical",
      () => issueGrants(catalog, sue, { bases: ["/org=a/"] }),
      "place",
    ],
    ["no base at all", () => issueGrants(catalog, sue, { bases: [] }), "place"],
    [
      "statements that are not a list",
      () => issueGrants(catalog, { subject: "sue", statements: {} as unknown as Statement[] }),
      "statement",
    ],
  ])("refuses %s as malformed", (_, run, what) => {
    expect(refused(run)).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what } });
  });

  it("refuses a base outside the structure", () => {
    expect(refused(() => issueGrants(catalog, sue, { bases: ["/unit=u7"] }))).toMatchObject({
      code: "ERR_AUTHZ_PLACE_OUTSIDE",
      cause: { place: "/unit=u7" },
    });
  });
});
