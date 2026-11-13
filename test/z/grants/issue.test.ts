import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../../src/z/catalog.ts";
import { could, issueGrants } from "../../../src/z/grants.ts";
import type { GrantsPart, Statement, StoredRole, SubjectStatements } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

const MONDAY = 1794214800;
const FRIDAY = 1794528000;
const NEXT_MONDAY = 1794819600;
const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";
const BY_NAME: GrantsPart[] = ["presets"];

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
  presets: { writer: ["report:write", "chat:send"], viewer: ["report:read"], staff: ["viewer"] },
  places: { "/": ["org", "server"], "org": ["area", "unit"], "area": ["archive"] },
});

const flat = defineCatalog({
  permissions: ["post:read", "post:write"],
  presets: { viewer: ["*:read"], editor: ["viewer", "post:write"] },
  places: false,
});

const ada = defineCatalog({
  permissions: ["billing:read", "post:read", "report:read", "report:write"],
  presets: { viewer: ["*:read"] },
  places: { "/": ["org"], "org": ["unit"] },
});

function issue(
  statements: Statement[],
  options?: { subject?: string; bases?: string[]; roles?: StoredRole[]; omit?: GrantsPart[] },
) {
  const read = { subject: options?.subject ?? "sue", statements, roles: options?.roles };
  return issueGrants(catalog, read, {
    bases: options?.bases,
    omit: options?.omit,
    now: () => MONDAY * 1000,
  });
}

describe("the examples of the grants object", () => {
  it("writes Zoe's allow and her own exclusion at the organisation, alike in both modes", () => {
    const statements: Statement[] = [
      { kind: "allow", subject: "zoe", value: "report:*", place: ACME },
      { kind: "exclude", subject: "zoe", value: "report:write", place: ACME },
    ];
    const expected = {
      v: "1",
      ct: catalog.fingerprint,
      at: MONDAY,
      pl: [ACME],
      nt: { "report:*": { a: [[0]] }, "report:write": { x: [[0]] } },
    };
    expect(issue(statements, { subject: "zoe" })).toStrictEqual(expected);
    expect(issue(statements, { subject: "zoe", omit: BY_NAME })).toStrictEqual(expected);
  });

  const sue: Statement[] = [
    { kind: "assign", subject: "team", value: "writer", place: ACME },
    { kind: "exclude", subject: "team", value: "report:write", place: ARCHIVES },
    { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
  ];

  it("writes Sue's team as bundle 1 and her own allow in no bundle, with presets by name", () => {
    expect(issue(sue, { omit: BY_NAME })).toStrictEqual({
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

  it("writes Sue's grants with a copy of `writer`, naming every permission by its position", () => {
    expect(issue(sue)).toStrictEqual({
      v: "1",
      ct: catalog.fingerprint,
      at: MONDAY,
      pl: [ACME, ARCHIVES],
      pm: ["chat:send", "report:write"],
      ps: { writer: [0, 1] },
      nt: {
        "1": { a: [[0, FRIDAY]], x: [[1, null, 1]] },
        "writer": { a: [[0, null, 1]] },
      },
    });
  });

  const ed: Statement[] = [
    { kind: "assign", subject: "ed", value: "viewer" },
    { kind: "assign", subject: "ed", value: "editor", expiresAt: NEXT_MONDAY },
  ];

  it("writes Ed's two presets by name with no place table in a flat application", () => {
    const grants = issueGrants(
      flat,
      { subject: "ed", statements: ed },
      { omit: BY_NAME, now: () => MONDAY * 1000 },
    );
    expect(grants).toStrictEqual({
      v: "1",
      ct: flat.fingerprint,
      at: MONDAY,
      nt: { editor: { a: [[null, NEXT_MONDAY]] }, viewer: { a: [[]] } },
    });
  });

  it("writes Ed's two presets as copies, `post:write` in the permission table", () => {
    const grants = issueGrants(
      flat,
      { subject: "ed", statements: ed },
      { now: () => MONDAY * 1000 },
    );
    expect(grants).toStrictEqual({
      v: "1",
      ct: flat.fingerprint,
      at: MONDAY,
      pm: ["post:write"],
      ps: { editor: [0, "viewer"], viewer: ["*:read"] },
      nt: { editor: { a: [[null, NEXT_MONDAY]] }, viewer: { a: [[]] } },
    });
  });

  const adaRead = {
    subject: "ada",
    statements: [
      { kind: "assign", subject: "ada", value: "reviewer", place: ACME },
      { kind: "allow", subject: "ada", value: "billing:read", place: `${ACME}/unit=u7` },
    ] satisfies Statement[],
    roles: [{ name: "reviewer", entries: ["viewer", "report:write", "-billing:read"] }],
  };

  it("writes Ada's stored role under its name, the preset it references as a copy", () => {
    expect(issueGrants(ada, adaRead, { now: () => MONDAY * 1000 })).toStrictEqual({
      v: "1",
      ct: ada.fingerprint,
      at: MONDAY,
      pl: [ACME, `${ACME}/unit=u7`],
      pm: ["billing:read", "report:write"],
      ps: { viewer: ["*:read"] },
      sr: { reviewer: ["-0", 1, "viewer"] },
      nt: { "0": { a: [[1]] }, "reviewer": { a: [[0]] } },
    });
  });

  it("writes Ada's stored role with the preset it references by name", () => {
    expect(issueGrants(ada, adaRead, { omit: BY_NAME, now: () => MONDAY * 1000 })).toStrictEqual({
      v: "1",
      ct: ada.fingerprint,
      at: MONDAY,
      pl: [ACME, `${ACME}/unit=u7`],
      pm: ["billing:read", "report:write"],
      sr: { reviewer: ["-0", 1, "viewer"] },
      nt: { "0": { a: [[1]] }, "reviewer": { a: [[0]] } },
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
    const grants = issue(
      [
        { kind: "assign", subject: "bob", value: "writer", place: ACME },
        { kind: "exclude", subject: "bob", value: "report:write", place: ARCHIVES },
        { kind: "exclude", subject: "sue", value: "chat:send", place: ARCHIVES },
      ],
      { omit: BY_NAME },
    );
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

  it("keeps as written what is inert under the catalog of issue, for a later catalog to read", () => {
    const grants = issue([
      { kind: "allow", subject: "sue", value: "invoice:read" },
      { kind: "deny", subject: "sue", value: "invoice:*" },
      { kind: "exclude", subject: "sue", value: "*:approve", place: ACME },
      { kind: "allow", subject: "sue", value: "chat:read", place: "/unit=u7" },
    ]);
    expect(grants).not.toHaveProperty("pm");
    expect(grants.pl).toStrictEqual([ACME, "/unit=u7"]);
    expect(grants.nt).toStrictEqual({
      "*:approve": { x: [[0]] },
      "chat:read": { a: [[1]] },
      "invoice:*": { d: [[]] },
      "invoice:read": { a: [[]] },
    });
  });

  it("keeps an assignment whose role resolves but gives nothing, with its definition", () => {
    const grants = issue(
      [
        { kind: "assign", subject: "sue", value: "none" },
        { kind: "assign", subject: "sue", value: "nothing", place: "/org=globex" },
        { kind: "assign", subject: "sue", value: "hollow" },
        { kind: "assign", subject: "sue", value: "unknown", place: "/unit=u7" },
      ],
      {
        roles: [
          { name: "none", entries: [] },
          { name: "nothing", entries: ["invoice:*"] },
          { name: "hollow", entries: ["chat:send", "-chat:send"] },
          { name: "unknown", entries: ["invoice:read", "-invoice:read"] },
        ],
      },
    );
    expect(grants.pm).toStrictEqual(["chat:send", "invoice:read"]);
    expect(grants.sr).toStrictEqual({
      hollow: ["-0", 0],
      none: [],
      nothing: ["invoice:*"],
      unknown: ["-1", 1],
    });
    expect(grants.nt).toStrictEqual({
      hollow: { a: [[]] },
      none: { a: [[]] },
      nothing: { a: [[0]] },
      unknown: { a: [[1]] },
    });
  });
});

describe("roles that cannot be resolved at issue", () => {
  const roles: StoredRole[] = [
    { name: "broken", entries: ["chat:read", "ghost"] },
    { name: "above", entries: ["report:read", "broken"] },
    { name: "minus", entries: ["chat:send", "-ghost"] },
    { name: "looped", entries: ["chat:read", "-other"] },
    { name: "other", entries: ["looped"] },
    { name: "fine", entries: ["match:join"] },
  ];
  const others = defineCatalog({ ...catalog.data, presets: { viewer: ["chat:read"] } });

  it.each([
    ["with copies", undefined],
    ["by name", BY_NAME],
  ])("leave out an assignment of a role that names a role existing nowhere, %s", (_, omit) => {
    const grants = issue(
      [
        { kind: "assign", subject: "sue", value: "broken", place: ACME },
        { kind: "allow", subject: "sue", value: "chat:read" },
      ],
      { roles, omit },
    );
    expect(grants).toStrictEqual({
      v: "1",
      ct: catalog.fingerprint,
      at: MONDAY,
      nt: { "chat:read": { a: [[]] } },
    });
    const at = { now: () => MONDAY * 1000 };
    expect(could(others, grants, { permission: "chat:read", place: ACME }, at)).toMatchObject({
      allowed: true,
      by: { kind: "allow", value: "chat:read" },
    });
  });

  it("leave out a role that references a broken role, or excludes one, and both roles of a cycle", () => {
    const grants = issue(
      ["above", "minus", "looped", "other", "fine"].map((value): Statement => ({
        kind: "assign",
        subject: "sue",
        value,
      })),
      { roles },
    );
    expect(grants.sr).toStrictEqual({ fine: [0] });
    expect(grants.pm).toStrictEqual(["match:join"]);
    expect(grants.nt).toStrictEqual({ fine: { a: [[]] } });
  });
});

describe("definitions", () => {
  const roles: StoredRole[] = [
    { name: "desk", entries: ["lead", "chat:send"] },
    { name: "lead", entries: ["staff", "-match:join"] },
    { name: "viewer", entries: ["access:manage"] },
    { name: "loose", entries: ["chat:read"] },
  ];
  const statements: Statement[] = [
    { kind: "assign", subject: "sue", value: "desk", place: ACME },
    { kind: "assign", subject: "sue", value: "viewer", place: "/server=s1" },
  ];

  it("write every role assigned and every role reached through references, presets as copies", () => {
    const grants = issue(statements, { roles });
    expect(grants.pm).toStrictEqual(["chat:send", "match:join", "report:read"]);
    expect(grants.ps).toStrictEqual({ staff: ["viewer"], viewer: [2] });
    expect(grants.sr).toStrictEqual({ desk: [0, "lead"], lead: ["-1", "staff"] });
    expect(grants.nt).toStrictEqual({ desk: { a: [[0]] }, viewer: { a: [[1]] } });
  });

  it("write the stored roles alone with presets by name, a stored role named like a preset never", () => {
    const grants = issue(statements, { roles, omit: BY_NAME });
    expect(grants.pm).toStrictEqual(["chat:send", "match:join"]);
    expect(grants).not.toHaveProperty("ps");
    expect(grants.sr).toStrictEqual({ desk: [0, "lead"], lead: ["-1", "staff"] });
  });

  it("write a permission table only when a definition is written and something names a concrete permission", () => {
    const bossy: Statement[] = [
      { kind: "assign", subject: "sue", value: "boss", place: ACME },
      { kind: "allow", subject: "sue", value: "chat:read" },
    ];
    const boss = [{ name: "boss", entries: ["staff", "-*:send"] }];
    const copies = issue(bossy, { roles: boss });
    expect(copies.pm).toStrictEqual(["chat:read", "report:read"]);
    expect(copies.ps).toStrictEqual({ staff: ["viewer"], viewer: [1] });
    expect(copies.sr).toStrictEqual({ boss: ["-*:send", "staff"] });
    expect(copies.nt).toStrictEqual({ "0": { a: [[]] }, "boss": { a: [[0]] } });
    const named = issue(bossy.slice(0, 1), { roles: boss, omit: BY_NAME });
    expect(named).not.toHaveProperty("pm");
    expect(named).not.toHaveProperty("ps");
    expect(named.sr).toStrictEqual({ boss: ["-*:send", "staff"] });
    const plain = issue(bossy.slice(1), { roles: boss });
    expect(plain).toStrictEqual({
      v: "1",
      ct: catalog.fingerprint,
      at: MONDAY,
      nt: { "chat:read": { a: [[]] } },
    });
  });

  it("write no definition of a role whose assignment sits outside every base", () => {
    const grants = issue(
      [
        { kind: "assign", subject: "sue", value: "desk", place: "/server=s1" },
        { kind: "assign", subject: "sue", value: "lead", place: "/org=globex" },
      ],
      {
        bases: ["/server=s1"],
        roles: [
          { name: "lead", entries: ["access:manage"] },
          { name: "desk", entries: ["chat:send"] },
        ],
      },
    );
    expect(grants.pm).toStrictEqual(["chat:send"]);
    expect(grants.sr).toStrictEqual({ desk: [0] });
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
    const grants = issue(statements, { omit: BY_NAME });
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
    const grants = issue(red, { bases: ["/org=acme/unit=u7"], omit: BY_NAME });
    expect(grants.nt).toStrictEqual({ "chat:read": { x: [[0]] }, "writer": { a: [[0]] } });
  });

  it("count an exclusion inert under the catalog of issue", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "red", value: "chat:read" },
        { kind: "exclude", subject: "red", value: "invoice:read", place: ACME },
      ],
      { omit: BY_NAME },
    );
    expect(grants.nt).toStrictEqual({
      "chat:read": { a: [[null, null, 1]] },
      "invoice:read": { x: [[0, null, 1]] },
    });
  });
});

describe("a permanent allow of `*` at the root", () => {
  it("carries its subject's denies and exclusions, and its groups', like any other", () => {
    const grants = issue(
      [
        { kind: "allow", subject: "ops", value: "*" },
        { kind: "deny", subject: "sue", value: "report:read", place: ACME },
        { kind: "exclude", subject: "ops", value: "chat:*", place: ACME },
        { kind: "assign", subject: "ops", value: "writer", place: ACME },
      ],
      { omit: BY_NAME },
    );
    expect(grants.nt).toStrictEqual({
      "*": { a: [[null, null, 1]] },
      "chat:*": { x: [[0, null, 1]] },
      "report:read": { d: [[0]] },
      "writer": { a: [[0, null, 1]] },
    });
  });
});

describe("stored roles handed in", () => {
  it("keep a preset under its own name when a stored role has the same name", () => {
    const roles = [{ name: "viewer", entries: ["chat:send"] }];
    const assign: Statement[] = [{ kind: "assign", subject: "sue", value: "viewer" }];
    expect(issue(assign, { roles, omit: BY_NAME })).not.toHaveProperty("sr");
    const copies = issue(assign, { roles });
    expect(copies).not.toHaveProperty("sr");
    expect(copies.ps).toStrictEqual({ viewer: [0] });
    expect(copies.pm).toStrictEqual(["report:read"]);
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

  it("refuse a role whose definition is written with an entry out of its form", () => {
    const roles: StoredRole[] = [{ name: "desk", entries: ["Chat:Read"] }];
    expect(
      refused(() => issue([{ kind: "assign", subject: "sue", value: "desk" }], { roles })),
    ).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what: "entry", value: "Chat:Read" } });
  });
});

describe("stable output", () => {
  const statements: Statement[] = [
    { kind: "assign", subject: "team", value: "writer", place: ACME },
    { kind: "exclude", subject: "team", value: "report:write", place: ARCHIVES },
    { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
    { kind: "allow", subject: "sue", value: "report:write", place: ARCHIVES },
    { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
    { kind: "allow", subject: "sue", value: "chat:*" },
    { kind: "assign", subject: "sue", value: "desk" },
  ];
  const roles: StoredRole[] = [
    { name: "desk", entries: ["staff", "chat:send", "-match:join", "chat:send"] },
  ];

  it.each([
    ["with copies", undefined],
    ["by name", BY_NAME],
  ])(
    "writes the same object, member for member, whatever order the input comes in, %s",
    (_, omit) => {
      const one = JSON.stringify(issue(statements, { roles, omit }));
      const two = JSON.stringify(
        issue(statements.toReversed(), {
          roles: roles.map((role) => ({ ...role, entries: role.entries.toReversed() })),
          omit,
        }),
      );
      expect(two).toBe(one);
    },
  );

  it("sorts items and writes each once", () => {
    expect(issue(statements, { omit: BY_NAME, roles }).nt["2"]?.a).toStrictEqual([
      [0, FRIDAY],
      [1],
    ]);
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
    [
      "an `omit` naming a part that does not exist",
      () => issueGrants(catalog, sue, { omit: ["preset" as GrantsPart] }),
      "omit",
    ],
    [
      "an `omit` that is not a list",
      () => issueGrants(catalog, sue, { omit: "presets" as unknown as GrantsPart[] }),
      "omit",
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
