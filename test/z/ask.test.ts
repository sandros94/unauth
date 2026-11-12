import { describe, expect, expectTypeOf, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
import { blocks, decidePermission } from "../../src/z/_internal/decide.ts";
import { roleReader } from "../../src/z/_internal/roles.ts";
import { readStatements } from "../../src/z/_internal/statements.ts";
import { ask } from "../../src/z/ask.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import type { Question, Statement, StoredRole, SubjectStatements } from "../../src/z/types.ts";
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
});

const NOW = 1794214800;
type P = (typeof catalog.data.permissions)[number];
type Asked = Question<P> & { subject?: string; groups?: readonly string[] };

/** What the application reads for a subject: the statements about it and about each of its groups. */
function applying(
  statements: readonly Statement[],
  subject: string,
  groups: readonly string[] = [],
): Statement[] {
  const identifiers = new Set([subject, ...groups]);
  return statements.filter((statement) => identifiers.has(statement.subject));
}

function answer(
  statements: Statement[],
  question: Asked,
  options?: { roles?: StoredRole[]; at?: number },
) {
  const { subject = "alice", groups, ...asked } = question;
  return ask(
    catalog,
    { subject, statements: applying(statements, subject, groups), roles: options?.roles },
    asked,
    { now: () => (options?.at ?? NOW) * 1000 },
  );
}
const allowed = (
  statements: Statement[],
  question: Asked,
  options?: { roles?: StoredRole[]; at?: number },
) => answer(statements, question, options).allowed;

describe("nothing stated (G1)", () => {
  it("denies, and names no statement", () => {
    const decision = answer([], { permission: "report:read" });
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
    const decision = answer(statements, { subject: "bob", permission: "report:write", place });
    expect(decision.by).toBe(statements[2]);
  });
});

describe("denies (G2, G3, G7)", () => {
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
    expect(answer(statements, { ...tom, place: "/org=acme/unit=u7" }).by).toBe(statements[1]);
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

describe("what is given (G4, Section 7)", () => {
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
    expect(answer(workspace, { ...mona, place: archives }).by).toBe(workspace[0]);
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
    expect(answer(sue, question, { at: 1794441600 }).by).toBe(sue[3]);
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
    expect(answer(statements, { ...mona, place: `${archives}/archive=2024` }).by).toBe(
      statements[4],
    );
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
    expect(answer(statements, { ...question, place: "/org=acme/report=q3" }).by).toBe(
      statements[2],
    );
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

describe("nobody stands above a statement (Section 12)", () => {
  const statements: Statement[] = [
    { kind: "allow", subject: "owner", value: "*" },
    { kind: "allow", subject: "deploy", value: "*", place: "/" },
    { kind: "deny", subject: "owner", value: "report:read", place: "/org=acme" },
    { kind: "exclude", subject: "owner", value: "event:*", place: "/org=acme" },
    { kind: "deny", subject: "staff", value: "access:manage" },
  ];

  it("denies a permanent allow of `*` at the root where a deny names its subject", () => {
    const decision = answer(statements, {
      subject: "owner",
      permission: "report:read",
      place: "/org=acme/unit=u7",
    });
    expect(decision).toStrictEqual({ allowed: false, covered: true, by: statements[2] });
    expect(
      allowed(statements, { subject: "owner", permission: "report:read", place: "/org=globex" }),
    ).toBe(true);
  });

  it("takes out what an exclusion names from a permanent allow of `*` at the root", () => {
    expect(
      allowed(statements, { subject: "owner", permission: "event:read", place: "/org=acme" }),
    ).toBe(false);
    expect(
      allowed(statements, { subject: "owner", permission: "chat:send", place: "/org=acme" }),
    ).toBe(true);
  });

  it("denies a group's deny to a member that holds `*` at the root through another group", () => {
    const question = {
      subject: "job",
      groups: ["staff", "deploy"],
      permission: "access:manage",
    } as const;
    expect(answer(statements, question)).toStrictEqual({
      allowed: false,
      covered: true,
      by: statements[4],
    });
    expect(answer(statements, { ...question, permission: "chat:send" }).by).toBe(statements[1]);
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
    const read = { subject: "alice", statements };
    const decision = ask(catalog, read, { permission: "report:read" }, { now });
    expect(decision.allowed).toBe(true);
    expect(reads).toBe(1);
    expect(ask(catalog, read, { permission: "report:read" }).allowed).toBe(false);
    expect(
      refused(() => ask(catalog, read, { permission: "report:read" }, { now: () => -1000 })),
    ).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "time" },
    });
  });
});

describe("statements that cannot bear on the question (G5)", () => {
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
      { kind: "allow", subject: "writers", value: "*", place: "/org=globex" },
      { kind: "assign", subject: "writers", value: "lead", expiresAt: NOW },
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
      { kind: "assign", subject: "writers", value: "lead", place: "/org=globex" },
      { kind: "exclude", subject: "alice", value: "post:*" },
    ];
    const permissions = [
      "report:write",
      "chat:send",
      "event:read",
      "report:read",
      "audit-log:delete",
    ] as const;
    const read = (statements: Statement[]) => ({ subject: "alice", statements });
    const now = () => NOW * 1000;
    for (const place of [
      "/",
      "/org=acme",
      "/org=acme/area=archives",
      "/org=acme/area=archives/archive=2019",
    ]) {
      for (const permission of permissions) {
        const question = { permission, place };
        const alone = ask(catalog, read(needed), question, { now });
        expect(ask(catalog, read([...unrelated, ...needed]), question, { now })).toEqual(alone);
        expect(ask(catalog, read([...needed, ...unrelated]), question, { now })).toEqual(alone);
      }
    }
  });
});

describe("every statement handed in applies (Section 7)", () => {
  it("counts a statement about another identifier as one of its groups', a deny included", () => {
    const statements: Statement[] = [
      { kind: "allow", subject: "alice", value: "report:read" },
      { kind: "deny", subject: "mallory", value: "report:read", place: "/org=acme" },
    ];
    const read = { subject: "alice", statements };
    const question = { permission: "report:read", place: "/org=acme" } as const;
    expect(ask(catalog, read, question, { now: () => NOW * 1000 })).toStrictEqual({
      allowed: false,
      covered: true,
      by: statements[1],
    });
    expect(ask(catalog, read, { permission: "report:read" }).by).toBe(statements[0]);
  });

  it("takes out, for an exclusion about another identifier, only what that identifier gave", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "team", value: "analyst", place: "/org=acme" },
      { kind: "exclude", subject: "team", value: "report:write", place: "/org=acme" },
      { kind: "assign", subject: "crew", value: "writer", place: "/org=acme" },
    ];
    const question = { permission: "report:write", place: "/org=acme" } as const;
    expect(ask(catalog, { subject: "bo", statements }, question).by).toBe(statements[2]);
    expect(
      ask(catalog, { subject: "bo", statements: statements.slice(0, 2) }, question).allowed,
    ).toBe(false);
  });

  it("takes out, for an exclusion about the subject's own identifier, what every identifier gave", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "team", value: "analyst", place: "/org=acme" },
      { kind: "exclude", subject: "bo", value: "report:write", place: "/org=acme" },
    ];
    const question = { permission: "report:write", place: "/org=acme" } as const;
    expect(ask(catalog, { subject: "bo", statements }, question).allowed).toBe(false);
    expect(ask(catalog, { subject: "team", statements }, question).allowed).toBe(true);
  });

  it("names a direct allow before an assignment, the subject's own before a group's", () => {
    const role: Statement = {
      kind: "assign",
      subject: "alice",
      value: "analyst",
      place: "/org=acme",
    };
    const direct: Statement = {
      kind: "allow",
      subject: "alice",
      value: "report:write",
      place: "/org=acme/unit=u7",
    };
    const reading: Statement = { kind: "allow", subject: "alice", value: "report:read" };
    const team: Statement = { kind: "allow", subject: "team", value: "report:write" };
    const at = {
      permission: "report:write",
      place: "/org=acme/unit=u7",
      groups: ["team"],
    } as const;
    expect(answer([role, direct], at).by).toBe(direct);
    expect(answer([direct, role], at).by).toBe(direct);
    expect(answer([role, reading], { ...at, permission: "report:read" }).by).toBe(reading);
    expect(answer([team, role], at).by).toBe(role);
    expect(answer([team, role, direct], at).by).toBe(direct);
    expect(answer([role], { ...at, place: "/org=acme" }).by).toBe(role);
  });

  it("names the very statement handed in, typed as the application's own", () => {
    type Row = Statement & { id: number };
    const rows: Row[] = [{ id: 7, kind: "allow", subject: "alice", value: "report:read" }];
    const read: SubjectStatements<Row> = { subject: "alice", statements: rows };
    const decision = ask(catalog, read, { permission: "report:list" });
    expect(decision.by).toBe(rows[0]);
    expectTypeOf(decision.by).toEqualTypeOf<Row | undefined>();
  });
});

describe("stored roles through assignments", () => {
  const roles: StoredRole[] = [
    { name: "editor", entries: ["analyst", "post:*", "-post:publish"] },
    { name: "broken", entries: ["post:read", "deleted"] },
    { name: "looped", entries: ["post:read", "-circle"] },
    { name: "circle", entries: ["report:read", "looped"] },
    { name: "analyst", entries: ["post:read"] },
  ];

  it("give what they resolve to, wherever they are assigned", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "alice", value: "editor", place: "/org=acme/unit=u7" },
    ];
    const place = "/org=acme/unit=u7";
    expect(allowed(statements, { permission: "post:draft", place }, { roles })).toBe(true);
    expect(allowed(statements, { permission: "report:list", place }, { roles })).toBe(true);
    expect(allowed(statements, { permission: "post:publish", place }, { roles })).toBe(false);
    expect(answer(statements, { permission: "post:read", place }, { roles }).by).toBe(
      statements[0],
    );
  });

  it("give nothing when the role no longer exists, references one that does not, or sits on a cycle", () => {
    const statements: Statement[] = [
      { kind: "assign", subject: "alice", value: "deleted", place: "/org=acme" },
      { kind: "assign", subject: "alice", value: "broken", place: "/org=acme" },
      { kind: "assign", subject: "alice", value: "looped" },
      { kind: "assign", subject: "alice", value: "circle", place: "/org=acme" },
    ];
    for (const permission of ["post:read", "report:read"] as const) {
      expect(allowed(statements, { permission, place: "/org=acme" }, { roles })).toBe(false);
    }
  });

  it("read a name that is both a preset and a stored role as the preset", () => {
    const statements: Statement[] = [{ kind: "assign", subject: "alice", value: "analyst" }];
    expect(allowed(statements, { permission: "report:write" }, { roles })).toBe(true);
    expect(allowed(statements, { permission: "post:read" }, { roles })).toBe(false);
  });

  it("refuse two stored roles of one name", () => {
    const statements: Statement[] = [{ kind: "assign", subject: "alice", value: "editor" }];
    const twice = [...roles, { name: "editor", entries: ["post:read"] }];
    expect(
      refused(() => answer(statements, { permission: "post:read" }, { roles: twice })),
    ).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "editor", reason: "duplicate" },
    });
  });
});

describe("the question", () => {
  const read = { subject: "a", statements: [] };
  const reasons: [string, unknown, object][] = [
    ["no permission", {}, { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "empty" } }],
    [
      "an empty permission",
      { permission: "" },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "empty" } },
    ],
    [
      "a permission that is not a string",
      { permission: 7 },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "empty" } },
    ],
    [
      "a wildcard",
      { permission: "report:*" },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "wildcard" } },
    ],
    [
      "`*`",
      { permission: "*" },
      { code: "ERR_AUTHZ_QUESTION_INVALID", cause: { reason: "wildcard" } },
    ],
    [
      "an unknown permission",
      { permission: "invoice:read" },
      { code: "ERR_AUTHZ_PERMISSION_UNKNOWN", cause: { permission: "invoice:read" } },
    ],
    [
      "a misspelled permission",
      { permission: "Report:read" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "permission" } },
    ],
    [
      "`*:*`",
      { permission: "*:*" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "permission" } },
    ],
    [
      "a place outside the structure",
      { permission: "report:read", place: "/unit=u7" },
      { code: "ERR_AUTHZ_PLACE_OUTSIDE", cause: { place: "/unit=u7" } },
    ],
    [
      "a place not canonical",
      { permission: "report:read", place: "/org=acme/" },
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "place" } },
    ],
    ["no question", null, { code: "ERR_AUTHZ_MALFORMED", cause: { what: "question" } }],
  ];

  it.each(reasons)("is refused as a whole for %s", (_, question, error) => {
    expect(refused(() => ask(catalog, read, question as Question<P>))).toMatchObject({
      status: 400,
      ...error,
    });
  });

  it("reads `/` and an absent place as the root", () => {
    const rows: Statement[] = [{ kind: "allow", subject: "a", value: "report:read", place: "/" }];
    expect(allowed(rows, { subject: "a", permission: "report:read" })).toBe(true);
    expect(allowed(rows, { subject: "a", permission: "report:read", place: "/" })).toBe(true);
  });
});

describe("what is read", () => {
  const question = { permission: "report:read" } as const;
  const reasons: [string, unknown, string][] = [
    ["no read", null, "statement"],
    ["no subject", { statements: [] }, "subject"],
    ["an empty subject", { subject: "", statements: [] }, "subject"],
    ["a subject that is not a string", { subject: 7, statements: [] }, "subject"],
    ["statements that are not a list", { subject: "a", statements: {} }, "statement"],
    ["no statements", { subject: "a" }, "statement"],
    ["a statement not in its shape", { subject: "a", statements: [null] }, "statement"],
    ["roles that are not stored roles", { subject: "a", statements: [], roles: [7] }, "roles"],
  ];

  it.each(reasons)("is refused as malformed for %s", (_, read, what) => {
    expect(refused(() => ask(catalog, read as SubjectStatements, question))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      status: 400,
      cause: { what },
    });
  });

  it("is read after the question is checked", () => {
    const broken = { subject: "", statements: [null] } as unknown as SubjectStatements;
    expect(refused(() => ask(catalog, broken, { permission: "" as P })).code).toBe(
      "ERR_AUTHZ_QUESTION_INVALID",
    );
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
  const asked = { subject: "alice", place: "/org=acme", time: NOW };

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
