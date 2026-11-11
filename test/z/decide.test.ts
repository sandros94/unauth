import { describe, expect, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
import { blocks, decidePermission } from "../../src/z/_internal/decide.ts";
import { roleReader } from "../../src/z/_internal/roles.ts";
import { readStatements } from "../../src/z/_internal/statements.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import { decide } from "../../src/z/decide.ts";
import type { Question, Statement, StoredRole } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

const catalog = defineCatalog({
  permissions: [
    "report:list",
    "report:read",
    "report:write",
    "event:read",
    "event:manage",
    "chat:read",
    "chat:send",
    "match:join",
    "audit-log:delete",
    "post:read",
    "post:draft",
    "post:publish",
    "access:manage",
  ],
  implies: {
    "report:write": ["report:read"],
    "report:read": ["report:list"],
    "event:manage": ["event:read"],
  },
  presets: {
    analyst: ["report:write"],
    writer: ["report:write", "chat:send"],
    lead: ["report:*", "event:manage"],
    player: ["chat:*", "match:join"],
  },
  places: {
    "/": ["org", "server"],
    "org": ["unit", "report", "area", "project"],
    "area": ["archive"],
    "server": ["channel"],
  },
  manager: "access:manage",
});

const NOW = 1794214800;
type P = (typeof catalog.data.permissions)[number];
type Asked = Omit<Question<P>, "subject"> & { subject?: string };

function ask(
  statements: Statement[],
  question: Asked,
  options?: { roles?: StoredRole[]; at?: number },
) {
  return decide(
    catalog,
    { subject: "alice", ...question },
    { statements, roles: options?.roles, now: () => (options?.at ?? NOW) * 1000 },
  );
}
const allowed = (
  statements: Statement[],
  question: Asked,
  options?: { roles?: StoredRole[]; at?: number },
) => ask(statements, question, options).allowed;

describe("nothing stated (D1)", () => {
  it("denies, and names no statement", () => {
    const decision = ask([], { permission: "report:read" });
    expect(decision).toStrictEqual({ allowed: false, covered: true });
  });

  it("denies a subject the application reports no group for, however many statements its groups have", () => {
    const bindings: Statement[] = [{ kind: "assign", subject: "dev-team", value: "lead" }];
    expect(allowed(bindings, { permission: "report:read" })).toBe(false);
    expect(allowed(bindings, { permission: "report:read", groups: ["dev-team"] })).toBe(true);
  });
});

describe("implications (Section 5.1)", () => {
  const statements: Statement[] = [
    { kind: "assign", subject: "alice", value: "analyst", place: "/org=acme" },
    { kind: "assign", subject: "bob", value: "analyst", place: "/org=acme" },
    { kind: "deny", subject: "bob", value: "report:read", place: "/org=acme" },
  ];
  const place = "/org=acme/report=q3";
  const table: [P, boolean, boolean][] = [
    ["report:write", true, false],
    ["report:read", true, false],
    ["report:list", true, true],
  ];

  it.each(table)("answers %s for Alice and Bob as the table does", (permission, alice, bob) => {
    expect(allowed(statements, { permission, place })).toBe(alice);
    expect(allowed(statements, { subject: "bob", permission, place })).toBe(bob);
  });

  it("names the deny that reached up to what implies it", () => {
    const decision = ask(statements, { subject: "bob", permission: "report:write", place });
    expect(decision.by).toBe(statements[2]);
  });
});

describe("denies (D2, D3, D7)", () => {
  it("block from any covering place, about the subject or a group, and nothing lower undoes them", () => {
    const statements: Statement[] = [
      { kind: "allow", subject: "tom", value: "*", place: "/org=acme" },
      { kind: "deny", subject: "acme-members", value: "audit-log:delete", place: "/org=acme" },
      { kind: "allow", subject: "tom", value: "audit-log:delete", place: "/org=acme/unit=u7" },
    ];
    const tom = {
      subject: "tom",
      groups: ["acme-members"],
      permission: "audit-log:delete" as const,
    };
    expect(allowed(statements, { ...tom, place: "/org=acme" })).toBe(false);
    expect(ask(statements, { ...tom, place: "/org=acme/unit=u7" }).by).toBe(statements[1]);
    expect(allowed(statements, { ...tom, groups: [], place: "/org=acme/unit=u7" })).toBe(true);
  });

  it("are exact on what they name and complete on what includes it", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "alice", value: "lead" },
      { kind: "deny", subject: "alice", value: "event:manage" },
    ];
    expect(allowed(statements, { permission: "event:manage" })).toBe(false);
    expect(allowed(statements, { permission: "event:read" })).toBe(true);
    statements[1] = { kind: "deny", subject: "alice", value: "event:read" };
    expect(allowed(statements, { permission: "event:manage" })).toBe(false);
  });

  it("ignore depth: a root allow does not beat a narrow deny, nor a narrow allow a root deny", () => {
    const narrowDeny: Statement[] = [
      { kind: "allow", subject: "alice", value: "report:read" },
      { kind: "deny", subject: "alice", value: "report:read", place: "/org=acme/unit=u7" },
    ];
    expect(allowed(narrowDeny, { permission: "report:read", place: "/org=acme/unit=u7" })).toBe(
      false,
    );
    expect(allowed(narrowDeny, { permission: "report:read", place: "/org=acme/unit=u8" })).toBe(
      true,
    );
    const rootDeny: Statement[] = [
      { kind: "deny", subject: "alice", value: "report:read" },
      { kind: "allow", subject: "alice", value: "report:read", place: "/org=acme/unit=u7" },
    ];
    expect(allowed(rootDeny, { permission: "report:read", place: "/org=acme/unit=u7" })).toBe(
      false,
    );
  });

  it("with a wildcard block every permission it expands to, at its place and under it only", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "gil", value: "player", place: "/server=s1" },
      { kind: "deny", subject: "gil", value: "*:send", place: "/server=s1/channel=general" },
      { kind: "deny", subject: "gil", value: "*", place: "/server=s1/channel=nsfw" },
    ];
    const gil = { subject: "gil" };
    expect(
      allowed(statements, {
        ...gil,
        permission: "chat:send",
        place: "/server=s1/channel=general",
      }),
    ).toBe(false);
    expect(
      allowed(statements, {
        ...gil,
        permission: "chat:read",
        place: "/server=s1/channel=general",
      }),
    ).toBe(true);
    expect(
      allowed(statements, { ...gil, permission: "chat:send", place: "/server=s1/channel=help" }),
    ).toBe(true);
    expect(
      allowed(statements, { ...gil, permission: "chat:read", place: "/server=s1/channel=nsfw" }),
    ).toBe(false);
  });
});

describe("what is given (D4, Section 7)", () => {
  const archives = "/org=acme/area=archives";
  const workspace: Statement[] = [
    { kind: "assign", subject: "leads", value: "lead", place: "/org=acme" },
    { kind: "assign", subject: "writers", value: "writer", place: "/org=acme" },
    { kind: "exclude", subject: "writers", value: "report:write", place: archives },
  ];

  it("takes out, for an exclusion about a group, only what that group gave", () => {
    const mona = {
      subject: "mona",
      groups: ["writers", "leads"],
      permission: "report:write" as const,
    };
    const wes = { subject: "wes", groups: ["writers"], permission: "report:write" as const };
    expect(ask(workspace, { ...mona, place: archives }).by).toBe(workspace[0]);
    expect(allowed(workspace, { ...wes, place: archives })).toBe(false);
    expect(allowed(workspace, { ...wes, place: "/org=acme/project=p1" })).toBe(true);
    expect(allowed(workspace, { ...wes, permission: "chat:send", place: archives })).toBe(true);
  });

  it("leaves the subject's own allow standing under a group's exclusion", () => {
    const sue: Statement[] = [
      ...workspace,
      {
        kind: "allow",
        subject: "sue",
        value: "report:write",
        place: "/org=acme",
        expiresAt: 1794528000,
      },
    ];
    const question = {
      subject: "sue",
      groups: ["writers"],
      permission: "report:write" as const,
      place: archives,
    };
    expect(ask(sue, question, { at: 1794441600 }).by).toBe(sue[3]);
    expect(allowed(sue, question, { at: 1794614400 })).toBe(false);
    expect(allowed(sue, { ...question, place: "/org=acme" }, { at: 1794614400 })).toBe(true);
  });

  it("takes out, for an exclusion about the subject, what every identifier gave, and a narrower allow gives back", () => {
    const statements: Statement[] = [
      ...workspace,
      { kind: "exclude", subject: "mona", value: "report:write", place: archives },
      { kind: "allow", subject: "mona", value: "report:write", place: `${archives}/archive=2024` },
    ];
    const mona = {
      subject: "mona",
      groups: ["writers", "leads"],
      permission: "report:write" as const,
    };
    expect(allowed(statements, { ...mona, place: `${archives}/archive=2019` })).toBe(false);
    expect(ask(statements, { ...mona, place: `${archives}/archive=2024` }).by).toBe(statements[4]);
    expect(allowed(statements, { ...mona, place: `${archives}/archive=2031` })).toBe(false);
    expect(allowed(statements, { ...mona, place: "/org=acme/project=p1" })).toBe(true);
    expect(
      allowed(statements, {
        ...mona,
        permission: "report:read",
        place: `${archives}/archive=2019`,
      }),
    ).toBe(true);
  });

  it("gives back through a group placed narrower than the subject's exclusion", () => {
    const statements: Statement[] = [
      { kind: "allow", subject: "alice", value: "report:read" },
      { kind: "exclude", subject: "alice", value: "report:read", place: "/org=acme" },
      { kind: "assign", subject: "q3-team", value: "analyst", place: "/org=acme/report=q3" },
    ];
    const question = { groups: ["q3-team"], permission: "report:read" as const };
    expect(allowed(statements, { ...question, place: "/org=acme/report=q2" })).toBe(false);
    expect(ask(statements, { ...question, place: "/org=acme/report=q3" }).by).toBe(statements[2]);
  });

  it("wins at its own place, over what that place gives", () => {
    const statements: Statement[] = [
      { kind: "allow", subject: "alice", value: "report:*", place: "/org=acme" },
      { kind: "exclude", subject: "alice", value: "report:read", place: "/org=acme" },
      { kind: "allow", subject: "alice", value: "event:read", place: "/org=acme" },
      { kind: "exclude", subject: "alice", value: "event:read", place: "/org=acme" },
    ];
    const at = (permission: P) => allowed(statements, { permission, place: "/org=acme/unit=u7" });
    expect(at("report:read")).toBe(false);
    expect(at("report:write")).toBe(false);
    expect(at("report:list")).toBe(true);
    expect(at("event:read")).toBe(false);
  });

  it("is everything except one: excluded at a place, allowed in one room under it", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "gil", value: "player", place: "/server=s1" },
      { kind: "exclude", subject: "gil", value: "chat:send", place: "/server=s1" },
      { kind: "allow", subject: "gil", value: "chat:send", place: "/server=s1/channel=help" },
    ];
    const gil = { subject: "gil", permission: "chat:send" as const };
    expect(allowed(statements, { ...gil, place: "/server=s1/channel=lobby" })).toBe(false);
    expect(allowed(statements, { ...gil, place: "/server=s1/channel=help" })).toBe(true);
  });

  it("reads wildcards in allows and exclusions against the catalog", () => {
    const zoe: Statement[] = [
      { kind: "allow", subject: "zoe", value: "report:*", place: "/org=acme" },
      { kind: "exclude", subject: "zoe", value: "report:write", place: "/org=acme" },
      { kind: "allow", subject: "zoe", value: "*:read", place: "/org=globex" },
      { kind: "exclude", subject: "zoe", value: "*:read", place: "/org=globex/unit=u1" },
    ];
    const at = (permission: P, place: string) =>
      allowed(zoe, { subject: "zoe", permission, place });
    expect(at("report:read", "/org=acme")).toBe(true);
    expect(at("report:write", "/org=acme")).toBe(false);
    expect(at("event:read", "/org=globex")).toBe(true);
    expect(at("report:list", "/org=globex")).toBe(true);
    expect(at("chat:read", "/org=globex/unit=u1")).toBe(false);
    expect(at("report:list", "/org=globex/unit=u1")).toBe(false);
  });
});

describe("permanent managers (D9)", () => {
  const statements: Statement[] = [
    { kind: "allow", subject: "owner", value: "*" },
    { kind: "allow", subject: "deploy", value: "*", place: "/" },
    { kind: "deny", subject: "owner", value: "report:read", place: "/org=acme" },
    { kind: "exclude", subject: "owner", value: "*", place: "/org=acme" },
    { kind: "deny", subject: "staff", value: "access:manage" },
  ];

  it("are allowed everything everywhere, named by their permanent allow of `*`", () => {
    const decision = ask(statements, {
      subject: "owner",
      permission: "report:read",
      place: "/org=acme/unit=u7",
    });
    expect(decision.allowed).toBe(true);
    expect(decision.by).toBe(statements[0]);
    expect(
      ask(statements, { subject: "job", groups: ["staff", "deploy"], permission: "access:manage" })
        .by,
    ).toBe(statements[1]);
  });

  it("are not made by a `*` with an end or at a narrower place, which denies reach", () => {
    const others: Statement[] = [
      { kind: "allow", subject: "temp", value: "*", expiresAt: NOW + 3600 },
      { kind: "allow", subject: "tom", value: "*", place: "/org=acme" },
      { kind: "deny", subject: "temp", value: "report:read" },
      { kind: "deny", subject: "tom", value: "report:read", place: "/org=acme" },
    ];
    expect(allowed(others, { subject: "temp", permission: "report:write" })).toBe(false);
    expect(allowed(others, { subject: "temp", permission: "event:read" })).toBe(true);
    expect(allowed(others, { subject: "tom", permission: "report:list", place: "/org=acme" })).toBe(
      true,
    );
    expect(allowed(others, { subject: "tom", permission: "report:read", place: "/org=acme" })).toBe(
      false,
    );
  });
});

describe("time", () => {
  const at = NOW;
  it.each(["allow", "assign"] as const)("ends a %s at the second of its end", (kind) => {
    const value = kind === "allow" ? "report:read" : "analyst";
    const statements: Statement[] = [{ kind, subject: "alice", value, expiresAt: at }];
    expect(allowed(statements, { permission: "report:read" }, { at })).toBe(false);
    expect(allowed(statements, { permission: "report:read" }, { at: at - 1 })).toBe(true);
  });

  it.each(["deny", "exclude"] as const)("lifts a %s at the second of its end", (kind) => {
    const statements: Statement[] = [
      { kind: "allow", subject: "gil", value: "match:join" },
      { kind, subject: "gil", value: "match:join", expiresAt: at },
    ];
    expect(allowed(statements, { subject: "gil", permission: "match:join" }, { at })).toBe(true);
    expect(allowed(statements, { subject: "gil", permission: "match:join" }, { at: at - 1 })).toBe(
      false,
    );
  });

  it("reads the clock once, in seconds, and refuses one counting before the epoch", () => {
    let reads = 0;
    const now = () => {
      reads++;
      return NOW * 1000 + 999;
    };
    const statements: Statement[] = [
      { kind: "allow", subject: "alice", value: "report:read", expiresAt: NOW + 1 },
    ];
    const decision = decide(
      catalog,
      { subject: "alice", permission: "report:read" },
      { statements, now },
    );
    expect(decision.allowed).toBe(true);
    expect(reads).toBe(1);
    expect(
      refused(() =>
        decide(
          catalog,
          { subject: "a", permission: "report:read" },
          { statements, now: () => -1000 },
        ),
      ),
    ).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "time" },
    });
  });
});

describe("statements that cannot bear on the question (D5)", () => {
  it("are inert when they name nothing declared, and skipped when they sit outside the structure", () => {
    const statements: Statement[] = [
      { kind: "allow", subject: "alice", value: "report:read" },
      { kind: "deny", subject: "alice", value: "invoice:*" },
      { kind: "exclude", subject: "alice", value: "invoice:read" },
      { kind: "deny", subject: "alice", value: "report:read", place: "/unit=u7" },
      { kind: "allow", subject: "alice", value: "report:write", place: "/unit=u7" },
    ];
    expect(allowed(statements, { permission: "report:read" })).toBe(true);
    expect(allowed(statements, { permission: "report:write" })).toBe(false);
  });

  it("never apply at a neighbour with a similar key", () => {
    const statements: Statement[] = [
      { kind: "allow", subject: "alice", value: "report:read", place: "/org=acme" },
    ];
    expect(allowed(statements, { permission: "report:read", place: "/org=acme/unit=u7" })).toBe(
      true,
    );
    expect(allowed(statements, { permission: "report:read", place: "/org=acme-x" })).toBe(false);
  });

  it("never change an answer when handed in beside the ones needed", () => {
    const needed: Statement[] = [
      { kind: "assign", subject: "writers", value: "writer", place: "/org=acme" },
      {
        kind: "exclude",
        subject: "writers",
        value: "report:write",
        place: "/org=acme/area=archives",
      },
      {
        kind: "allow",
        subject: "alice",
        value: "event:manage",
        place: "/org=acme",
        expiresAt: NOW + 60,
      },
      { kind: "deny", subject: "alice", value: "chat:send", place: "/org=acme/area=archives" },
    ];
    const unrelated: Statement[] = [
      { kind: "deny", subject: "mallory", value: "*" },
      { kind: "allow", subject: "mallory", value: "*" },
      { kind: "deny", subject: "alice", value: "*", place: "/org=globex" },
      { kind: "deny", subject: "writers", value: "*", place: "/org=acme/project=p1" },
      {
        kind: "allow",
        subject: "alice",
        value: "*",
        place: "/org=acme/area=archives/archive=2024",
      },
      { kind: "deny", subject: "alice", value: "*", expiresAt: NOW },
      { kind: "exclude", subject: "alice", value: "*", expiresAt: NOW - 1 },
      { kind: "deny", subject: "alice", value: "gone:read" },
      { kind: "deny", subject: "alice", value: "*", place: "/unit=u7" },
      { kind: "assign", subject: "leads", value: "lead" },
      { kind: "exclude", subject: "alice", value: "post:*" },
    ];
    const questions: Asked[] = (
      ["report:write", "chat:send", "event:read", "report:read", "audit-log:delete"] as const
    ).map((permission) => ({ groups: ["writers"], permission }));
    for (const place of [
      "/",
      "/org=acme",
      "/org=acme/area=archives",
      "/org=acme/area=archives/archive=2019",
    ]) {
      for (const question of questions) {
        const alone = ask(needed, { ...question, place });
        expect(ask([...unrelated, ...needed], { ...question, place })).toEqual(alone);
        expect(ask([...needed, ...unrelated], { ...question, place })).toEqual(alone);
      }
    }
  });
});

describe("stored roles through assignments", () => {
  const roles: StoredRole[] = [
    { name: "editor", home: "/org=acme", entries: ["analyst", "post:*", "-post:publish"] },
    { name: "broken", home: "/org=acme", entries: ["post:read", "deleted"] },
  ];

  it("give what they resolve to at the place of the assignment", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "alice", value: "editor", place: "/org=acme/unit=u7" },
    ];
    const place = "/org=acme/unit=u7";
    expect(allowed(statements, { permission: "post:draft", place }, { roles })).toBe(true);
    expect(allowed(statements, { permission: "report:list", place }, { roles })).toBe(true);
    expect(allowed(statements, { permission: "post:publish", place }, { roles })).toBe(false);
    expect(ask(statements, { permission: "post:read", place }, { roles }).by).toBe(statements[0]);
  });

  it("give nothing when the role no longer exists, references one that does not, or is assigned above its home", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "alice", value: "deleted", place: "/org=acme" },
      { kind: "assign", subject: "alice", value: "broken", place: "/org=acme" },
      { kind: "assign", subject: "alice", value: "editor" },
    ];
    for (const permission of ["post:read", "report:read"] as const) {
      expect(allowed(statements, { permission, place: "/org=acme" }, { roles })).toBe(false);
    }
  });
});

describe("the question", () => {
  const statements: Statement[] = [];
  const reasons: [string, unknown, object][] = [
    [
      "no permission",
      { subject: "a" },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "empty" } },
    ],
    [
      "an empty permission",
      { subject: "a", permission: "" },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "empty" } },
    ],
    [
      "a permission that is not a string",
      { subject: "a", permission: 7 },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "empty" } },
    ],
    [
      "a wildcard",
      { subject: "a", permission: "report:*" },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "wildcard" } },
    ],
    [
      "`*`",
      { subject: "a", permission: "*" },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "wildcard" } },
    ],
    [
      "an unknown permission",
      { subject: "a", permission: "invoice:read" },
      { code: "ERR_AUTHZ_PERMISSION_UNKNOWN", cause: { permission: "invoice:read" } },
    ],
    [
      "a misspelled permission",
      { subject: "a", permission: "Report:read" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "permission" } },
    ],
    [
      "`*:*`",
      { subject: "a", permission: "*:*" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "permission" } },
    ],
    [
      "a place outside the structure",
      { subject: "a", permission: "report:read", place: "/unit=u7" },
      { code: "ERR_AUTHZ_PLACE_OUTSIDE", cause: { place: "/unit=u7" } },
    ],
    [
      "a place not canonical",
      { subject: "a", permission: "report:read", place: "/org=acme/" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "place" } },
    ],
    [
      "an empty subject",
      { subject: "", permission: "report:read" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "question" } },
    ],
    [
      "groups that are not strings",
      { subject: "a", groups: ["t", 7], permission: "report:read" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "question" } },
    ],
    [
      "groups that are not a list",
      { subject: "a", groups: "t", permission: "report:read" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "question" } },
    ],
    ["no question", null, { code: "ERR_AUTHZ_MALFORMED", cause: { what: "question" } }],
  ];

  it.each(reasons)("is refused as a whole for %s", (_, question, error) => {
    expect(refused(() => decide(catalog, question as Question<P>, { statements }))).toMatchObject({
      status: 400,
      ...error,
    });
  });

  it("is checked before the statements are read", () => {
    expect(
      refused(() =>
        decide(catalog, { subject: "a", permission: "" as P }, { statements: [null as never] }),
      ),
    ).toMatchObject({
      code: "ERR_AUTHZ_QUESTION_INVALID",
    });
    expect(
      refused(() =>
        decide(
          catalog,
          { subject: "a", permission: "report:read" },
          { statements: [null as never] },
        ),
      ),
    ).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "statement" },
    });
  });

  it("reads `/` and an absent place as the root", () => {
    const rows: Statement[] = [{ kind: "allow", subject: "a", value: "report:read", place: "/" }];
    expect(allowed(rows, { subject: "a", permission: "report:read" })).toBe(true);
    expect(allowed(rows, { subject: "a", permission: "report:read", place: "/" })).toBe(true);
  });
});

describe("the decision core", () => {
  const compiled = compiledOf(catalog);
  const rows: Statement[] = [
    {
      kind: "assign",
      subject: "writers",
      value: "writer",
      place: "/org=acme",
      expiresAt: NOW + 100,
    },
    { kind: "deny", subject: "alice", value: "report:read", place: "/org=acme/area=archives" },
  ];
  const source = {
    catalog: compiled,
    roles: roleReader(compiled, []),
    statements: readStatements(compiled, rows),
  };
  const asked = { subject: "alice", groups: ["writers"], place: "/org=acme", time: NOW };

  it("answers one permission at a given place and time, without reading anything again", () => {
    expect(decidePermission(source, { ...asked, permission: "report:write" })).toMatchObject({
      allowed: true,
    });
    expect(
      decidePermission(source, { ...asked, permission: "report:write", time: NOW + 100 }).allowed,
    ).toBe(false);
    expect(
      decidePermission(source, {
        ...asked,
        permission: "report:write",
        place: "/org=acme/area=archives",
      }).by?.source,
    ).toBe(rows[1]);
  });

  it("names the deny that blocks, and tells a deny that blocks a permission", () => {
    const archives = { ...asked, place: "/org=acme/area=archives/archive=1" };
    const list = decidePermission(source, { ...archives, permission: "report:list" });
    expect([list.allowed, list.by?.source]).toStrictEqual([true, rows[0]]);
    const write = decidePermission(source, { ...archives, permission: "report:write" });
    expect([write.allowed, write.by?.source]).toStrictEqual([false, rows[1]]);
    const [, deny] = source.statements;
    expect(blocks(compiled, deny!, "report:write")).toBe(true);
    expect(blocks(compiled, deny!, "report:list")).toBe(false);
    expect(blocks(compiled, source.statements[0]!, "report:write")).toBe(false);
  });
});
