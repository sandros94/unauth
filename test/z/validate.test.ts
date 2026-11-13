import { describe, expect, expectTypeOf, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import type { Statement, StoredRole, ValidationIssue } from "../../src/z/types.ts";
import {
  assertRole,
  assertStatement,
  validateRole,
  validateStatement,
} from "../../src/z/validate.ts";
import { refused } from "./_expect.ts";

const catalog = defineCatalog({
  permissions: ["report:list", "report:read", "report:write", "chat:read", "chat:send"],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: { viewer: ["report:read"], owner: ["*"] },
  places: { "/": ["org"], "org": ["unit"] },
});

const role = (name: string, entries: string[]): StoredRole => ({ name, entries });
const desk = role("desk", ["viewer", "chat:send"]);
const brief = (issues: ValidationIssue[]) => issues.map(({ code, path }) => [code, path]);

describe("validateStatement", () => {
  const NOW = 1794214800;
  const now =
    (at: number = NOW) =>
    () =>
      at * 1000;
  const issues = (statement: unknown, roles?: StoredRole[], at: number = NOW) =>
    validateStatement(catalog, statement, { roles, now: now(at) });

  it("looks nothing up for a value whose kind is not one of the four, since the kind says what it names", () => {
    expect(brief(issues({ kind: "alow", subject: "sue", value: "report:raed" }))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["kind"]],
    ]);
    expect(brief(issues({ kind: "asign", subject: "sue", value: "ghost" }))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["kind"]],
    ]);
    expect(brief(issues({ kind: "alow", subject: "sue", value: "viewer" }))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["kind"]],
    ]);
    expect(brief(issues({ kind: "alow", subject: "sue", value: "Report Read!" }))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["kind"]],
      ["ERR_AUTHZ_MALFORMED", ["value"]],
    ]);
  });

  it("returns no issue for every kind written in its one form, extra members ignored", () => {
    for (const statement of [
      { kind: "allow", subject: "sue", value: "report:read" },
      { kind: "deny", subject: "team", value: "report:*", place: "/org=acme" },
      { kind: "exclude", subject: "sue", value: "*:read", place: "/org=acme/unit=u7" },
      { kind: "allow", subject: "owner", value: "*", place: "/" },
      { kind: "assign", subject: "sue", value: "viewer", expiresAt: 1794528000 },
      { kind: "assign", subject: "sue", value: "desk", place: "/org=acme" },
      { kind: "allow", subject: "sue", value: "chat:read", id: 7, note: "kept by the app" },
    ]) {
      expect(issues(statement, [desk])).toStrictEqual([]);
    }
  });

  it("accepts an end one second after the time, and the last second there is", () => {
    for (const expiresAt of [NOW + 1, 253402300799]) {
      expect(issues({ kind: "allow", subject: "sue", value: "chat:read", expiresAt })).toEqual([]);
    }
  });

  it("reports a statement that has ended: an end equal to the time or before it", () => {
    for (const expiresAt of [NOW, NOW - 1, 0]) {
      for (const kind of ["allow", "deny"]) {
        expect(issues({ kind, subject: "sue", value: "chat:read", expiresAt })).toStrictEqual([
          {
            code: "ERR_AUTHZ_STATEMENT_ENDED",
            path: ["expiresAt"],
            message: "The statement has already ended.",
            cause: { expiresAt },
          },
        ]);
      }
    }
  });

  it("reads the clock once, in seconds, and `Date.now` when none is given", () => {
    let reads = 0;
    const counted = () => {
      reads++;
      return NOW * 1000 + 999;
    };
    const statement = { kind: "allow", subject: "sue", value: "chat:read", expiresAt: NOW };
    expect(brief(validateStatement(catalog, statement, { now: counted }))).toStrictEqual([
      ["ERR_AUTHZ_STATEMENT_ENDED", ["expiresAt"]],
    ]);
    expect(reads).toBe(1);
    expect(
      validateStatement(catalog, { ...statement, expiresAt: NOW + 1 }, { now: counted }),
    ).toEqual([]);
    expect(brief(validateStatement(catalog, statement))).toStrictEqual([
      ["ERR_AUTHZ_STATEMENT_ENDED", ["expiresAt"]],
    ]);
  });

  it.each([
    ["not an object", null, []],
    ["a list", [], []],
    ["another kind", { kind: "grant", subject: "sue", value: "chat:read" }, ["kind"]],
    ["no kind", { subject: "sue", value: "chat:read" }, ["kind"]],
    ["an empty subject", { kind: "allow", subject: "", value: "chat:read" }, ["subject"]],
    [
      "a subject that is not a string",
      { kind: "allow", subject: 7, value: "chat:read" },
      ["subject"],
    ],
    ["no value", { kind: "allow", subject: "sue" }, ["value"]],
    [
      "a permission not in its one form",
      { kind: "allow", subject: "sue", value: "Chat:read" },
      ["value"],
    ],
    ["`*:*`", { kind: "deny", subject: "sue", value: "*:*" }, ["value"]],
    [
      "a role entry as a value",
      { kind: "exclude", subject: "sue", value: "-chat:read" },
      ["value"],
    ],
    [
      "a role name that is not a token",
      { kind: "assign", subject: "sue", value: "Desk" },
      ["value"],
    ],
    [
      "a permission assigned as a role",
      { kind: "assign", subject: "sue", value: "chat:read" },
      ["value"],
    ],
    [
      "a value that is neither, of no kind",
      { kind: "grant", subject: "sue", value: "Desk" },
      ["kind"],
    ],
  ])("reports %s as malformed", (_, statement, path) => {
    const found = issues(statement);
    expect(found[0]).toStrictEqual({
      code: "ERR_AUTHZ_MALFORMED",
      path,
      message: "The statement is not in its shape.",
      cause: { what: "statement", value: statement },
    });
  });

  it("reports a place that is not canonical as malformed", () => {
    for (const place of ["", "org=acme", "/org=acme/", "/org=%c3%a9", "/Org=acme"]) {
      expect(issues({ kind: "allow", subject: "sue", value: "chat:read", place })).toStrictEqual([
        {
          code: "ERR_AUTHZ_MALFORMED",
          path: ["place"],
          message: "The key of the place is not canonical.",
          cause: { what: "place", value: place },
        },
      ]);
    }
  });

  it("reports an end that is not a time as malformed", () => {
    for (const expiresAt of [-1, 1.5, 1794528000000, "1794528000", null]) {
      expect(
        issues({ kind: "allow", subject: "sue", value: "chat:read", expiresAt }),
      ).toStrictEqual([
        {
          code: "ERR_AUTHZ_MALFORMED",
          path: ["expiresAt"],
          message: "The time is not a count of seconds.",
          cause: { what: "time", value: expiresAt },
        },
      ]);
    }
  });

  it("reports a permission or a pattern that names no permission of the catalog", () => {
    for (const value of ["chat:kick", "billing:*", "*:delete"]) {
      for (const kind of ["allow", "deny", "exclude"]) {
        expect(issues({ kind, subject: "sue", value })).toStrictEqual([
          {
            code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
            path: ["value"],
            message: "The permission is not in the catalog.",
            cause: { permission: value },
          },
        ]);
      }
    }
  });

  it("reports a place that does not fit the structure", () => {
    const statement = { kind: "allow", subject: "sue", value: "chat:read", place: "/unit=u7" };
    expect(brief(issues(statement))).toStrictEqual([["ERR_AUTHZ_PLACE_OUTSIDE", ["place"]]]);
    expect(issues(statement)[0]?.cause).toStrictEqual({ place: "/unit=u7" });
  });

  it("reports an assignment of a role that is neither a preset nor handed in", () => {
    const statement = { kind: "assign", subject: "sue", value: "desk" };
    for (const roles of [undefined, [role("other", ["desk"])]]) {
      expect(issues(statement, roles)).toStrictEqual([
        {
          code: "ERR_AUTHZ_ROLE_INVALID",
          path: ["value"],
          message: "The role is neither a preset nor a stored role handed in.",
          cause: { role: "desk", reason: "unknown" },
        },
      ]);
    }
  });

  it("accepts an assignment of a stored role that resolves to nothing", () => {
    const roles = [role("loop", ["loop"]), role("stale", ["gone"])];
    for (const value of ["loop", "stale"]) {
      expect(issues({ kind: "assign", subject: "sue", value }, roles)).toStrictEqual([]);
    }
  });

  it("reports every independent problem at once, form first, then unknown, place, end", () => {
    const statement = {
      kind: "allow",
      subject: "",
      value: "chat:kick",
      place: "/unit=u7",
      expiresAt: NOW - 1,
    };
    expect(brief(issues(statement))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["subject"]],
      ["ERR_AUTHZ_PERMISSION_UNKNOWN", ["value"]],
      ["ERR_AUTHZ_PLACE_OUTSIDE", ["place"]],
      ["ERR_AUTHZ_STATEMENT_ENDED", ["expiresAt"]],
    ]);
    const ofNoKind = { ...statement, kind: "grant" };
    expect(brief(issues(ofNoKind))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["kind"]],
      ["ERR_AUTHZ_MALFORMED", ["subject"]],
      ["ERR_AUTHZ_PLACE_OUTSIDE", ["place"]],
      ["ERR_AUTHZ_STATEMENT_ENDED", ["expiresAt"]],
    ]);
  });

  it("skips a check that depends on one that failed", () => {
    const statement = {
      kind: "allow",
      subject: "sue",
      value: "Chat:kick",
      place: "/Unit=u7",
      expiresAt: 1.5,
    };
    expect(brief(issues(statement))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["value"]],
      ["ERR_AUTHZ_MALFORMED", ["place"]],
      ["ERR_AUTHZ_MALFORMED", ["expiresAt"]],
    ]);
    const mismatched = { kind: "assign", subject: "sue", value: "chat:kick" };
    expect(brief(issues(mismatched))).toStrictEqual([["ERR_AUTHZ_MALFORMED", ["value"]]]);
  });

  it("returns issues that survive JSON", () => {
    const found = issues({ kind: "allow", subject: 7, value: "chat:kick", expiresAt: 1 });
    expect(found).toHaveLength(3);
    expect(JSON.parse(JSON.stringify(found))).toStrictEqual(found);
  });

  it("throws for what is handed in beside the value: roles, a clock", () => {
    const statement = { kind: "assign", subject: "sue", value: "viewer" };
    expect(refused(() => issues(statement, [desk, desk]))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "desk", reason: "duplicate" },
    });
    expect(refused(() => issues(statement, [7 as never]))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "roles" },
    });
    expect(
      refused(() => validateStatement(catalog, statement, { now: () => -1000 })),
    ).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what: "time" } });
  });
});

describe("assertStatement", () => {
  const now = () => 1794214800 * 1000;

  it("returns for a valid statement and types it", () => {
    const value: unknown = { kind: "allow", subject: "sue", value: "chat:read", id: 7 };
    assertStatement(catalog, value, { now });
    expectTypeOf(value).toEqualTypeOf<Statement>();
    expect(value.subject).toBe("sue");
  });

  it("throws the first issue as the error it stands for", () => {
    for (const value of [
      { kind: "grant", subject: "", value: "chat:kick", expiresAt: 1 },
      { kind: "allow", subject: "sue", value: "chat:kick", expiresAt: 1 },
      { kind: "allow", subject: "sue", value: "chat:read", place: "/unit=u7", expiresAt: 1 },
      { kind: "assign", subject: "sue", value: "desk", expiresAt: 1 },
      { kind: "allow", subject: "sue", value: "chat:read", expiresAt: 1 },
    ]) {
      const [first] = validateStatement(catalog, value, { now });
      const error = refused(() => assertStatement(catalog, value, { now }));
      expect(first).toBeDefined();
      expect(error).toMatchObject({
        name: "UnauthError",
        status: 400,
        code: first?.code,
        message: first?.message,
        cause: first?.cause,
      });
    }
  });
});

describe("validateRole", () => {
  const issues = (definition: unknown, roles?: StoredRole[]) =>
    validateRole(catalog, definition, { roles });

  it("returns no issue for a role of permissions, patterns, presets, stored roles and exclusions", () => {
    expect(
      issues(role("lead", ["desk", "owner", "-viewer", "report:*", "-chat:read", "*:send"]), [
        desk,
      ]),
    ).toStrictEqual([]);
    expect(issues(role("empty", []))).toStrictEqual([]);
    expect(issues({ name: "desk", entries: ["viewer"], id: 7 })).toStrictEqual([]);
  });

  it("accepts the name of a preset, which reads as the preset", () => {
    expect(issues(role("viewer", ["chat:read"]))).toStrictEqual([]);
    expect(issues(role("viewer", ["viewer", "chat:read"]))).toStrictEqual([]);
  });

  it("replaces a handed-in role of its own name, as an edit does", () => {
    const roles = [role("a", ["b"]), role("b", ["chat:read"])];
    expect(issues(role("b", ["chat:send"]), roles)).toStrictEqual([]);
    expect(issues(role("b", ["a"]), roles)).toStrictEqual([
      {
        code: "ERR_AUTHZ_ROLE_INVALID",
        path: ["entries", 0],
        message: "The role's references form a cycle.",
        cause: { role: "b", reason: "cycle", reference: "b" },
      },
    ]);
  });

  it.each([
    ["not an object", null, "role", []],
    ["no entries", { name: "desk" }, "role", ["entries"]],
    ["entries that are not a list", { name: "desk", entries: "chat:read" }, "role", ["entries"]],
    ["a name that is not a token", role("Desk", ["chat:read"]), "role", ["name"]],
    ["an empty name", role("", ["chat:read"]), "role", ["name"]],
    ["`*:*`", role("desk", ["*:*"]), "entry", ["entries", 0]],
    ["`--chat:read`", role("desk", ["chat:read", "--chat:read"]), "entry", ["entries", 1]],
    ["an entry that is not a string", { name: "desk", entries: [7] }, "entry", ["entries", 0]],
    ["an uppercase entry", role("desk", ["Viewer"]), "entry", ["entries", 0]],
  ])("reports %s as malformed", (_, definition, what, path) => {
    const [first] = issues(definition);
    expect(first).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", path, cause: { what } });
  });

  it("reports an unknown permission or a pattern that matches none, excluded or not", () => {
    for (const entry of ["chat:kick", "-chat:kick", "billing:*", "-*:delete"]) {
      expect(issues(role("desk", ["chat:read", entry]))).toStrictEqual([
        {
          code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
          path: ["entries", 1],
          message: "The permission is not in the catalog.",
          cause: { permission: entry.replace(/^-/, "") },
        },
      ]);
    }
  });

  it("reports a reference, with or without `-`, to a role neither a preset nor handed in", () => {
    for (const entry of ["ghost", "-ghost"]) {
      expect(issues(role("desk", [entry]), [role("other", [])])).toStrictEqual([
        {
          code: "ERR_AUTHZ_ROLE_INVALID",
          path: ["entries", 0],
          message: "The role references a role that is neither a preset nor a stored role.",
          cause: { role: "desk", reason: "reference", reference: "ghost" },
        },
      ]);
    }
  });

  it("reports a reference through a handed-in role to a role that does not exist", () => {
    expect(issues(role("desk", ["stale"]), [role("stale", ["gone"])])).toMatchObject([
      { code: "ERR_AUTHZ_ROLE_INVALID", cause: { reason: "reference", reference: "gone" } },
    ]);
  });

  it("reports a cycle of references, with or without `-`", () => {
    for (const [definition, roles] of [
      [role("desk", ["desk"]), []],
      [role("desk", ["-desk"]), []],
      [role("desk", ["a"]), [role("a", ["-desk"])]],
      [role("desk", ["a"]), [role("a", ["b"]), role("b", ["a"])]],
    ] as const) {
      expect(issues(definition, [...roles])).toMatchObject([
        { code: "ERR_AUTHZ_ROLE_INVALID", path: ["entries", 0], cause: { reason: "cycle" } },
      ]);
    }
  });

  it("reports every independent problem at once, form first, each entry where it sits", () => {
    const definition = {
      name: "desk",
      entries: ["Viewer", "chat:kick", "ghost", "desk", 7, "owner"],
    };
    expect(brief(issues(definition))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["entries", 0]],
      ["ERR_AUTHZ_MALFORMED", ["entries", 4]],
      ["ERR_AUTHZ_PERMISSION_UNKNOWN", ["entries", 1]],
      ["ERR_AUTHZ_ROLE_INVALID", ["entries", 2]],
      ["ERR_AUTHZ_ROLE_INVALID", ["entries", 3]],
    ]);
  });

  it("still follows the references of a role whose name is not a token, which no role can name", () => {
    expect(brief(issues(role("Desk", ["ghost", "chat:kick", "Desk"])))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["name"]],
      ["ERR_AUTHZ_MALFORMED", ["entries", 2]],
      ["ERR_AUTHZ_ROLE_INVALID", ["entries", 0]],
      ["ERR_AUTHZ_PERMISSION_UNKNOWN", ["entries", 1]],
    ]);
    expect(brief(issues({ name: 7, entries: "chat:read" }))).toStrictEqual([
      ["ERR_AUTHZ_MALFORMED", ["name"]],
      ["ERR_AUTHZ_MALFORMED", ["entries"]],
    ]);
  });

  it("returns issues that survive JSON", () => {
    const found = issues({ name: "Desk", entries: ["chat:kick", 7] });
    expect(found).toHaveLength(3);
    expect(JSON.parse(JSON.stringify(found))).toStrictEqual(found);
  });

  it("throws for two handed-in roles of one name", () => {
    expect(
      refused(() => issues(role("lead", ["chat:read"]), [desk, role("desk", ["chat:read"])])),
    ).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "desk", reason: "duplicate" },
    });
  });
});

describe("assertRole", () => {
  it("returns for a valid role and types it", () => {
    const value: unknown = { name: "desk", entries: ["viewer"] };
    assertRole(catalog, value);
    expectTypeOf(value).toEqualTypeOf<StoredRole>();
    expect(value.entries).toStrictEqual(["viewer"]);
  });

  it("throws the first issue as the error it stands for", () => {
    for (const value of [
      { name: "Desk", entries: ["chat:kick"] },
      role("desk", ["chat:kick", "ghost"]),
      role("desk", ["ghost"]),
    ]) {
      const [first] = validateRole(catalog, value);
      const error = refused(() => assertRole(catalog, value));
      expect(error).toMatchObject({
        status: 400,
        code: first?.code,
        message: first?.message,
        cause: first?.cause,
      });
    }
  });
});
