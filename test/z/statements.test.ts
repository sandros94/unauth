import { describe, expect, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
import {
  identityOf,
  isPermanentManagement,
  isPermanentManager,
  permanentManagementOf,
  readStatement,
  readStatements,
} from "../../src/z/_internal/statements.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import type { Statement } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

const catalog = defineCatalog({
  permissions: ["report:read", "report:write", "access:manage"],
  presets: { viewer: ["report:read"] },
  places: { "/": ["org"], "org": ["unit"] },
  manager: "access:manage",
});
const compiled = compiledOf(catalog);
const read = (statement: unknown) => readStatement(compiled, statement);

describe("readStatement", () => {
  it("reads an absent place as the root and keeps the object handed in", () => {
    const row = { kind: "allow", subject: "alice", value: "report:read", id: 7 } as Statement;
    expect(read(row)).toEqual({
      kind: "allow",
      subject: "alice",
      value: "report:read",
      place: "/",
      expiresAt: undefined,
      source: row,
    });
    expect(read(row)?.source).toBe(row);
    const placed: Statement = {
      kind: "deny",
      subject: "team",
      value: "report:*",
      place: "/org=acme",
      expiresAt: 1794528000,
    };
    expect(read(placed)).toMatchObject({ place: "/org=acme", expiresAt: 1794528000 });
  });

  it("refuses a statement not in its shape", () => {
    const shapes: unknown[] = [
      null,
      "allow",
      [],
      { kind: "grant", subject: "a", value: "report:read" },
      { kind: "allow", subject: "", value: "report:read" },
      { kind: "allow", subject: 7, value: "report:read" },
      { kind: "allow", subject: "a", value: "" },
      { kind: "allow", subject: "a" },
      { kind: "allow", subject: "a", value: "Report:read" },
      { kind: "deny", subject: "a", value: "*:*" },
      { kind: "exclude", subject: "a", value: "-report:read" },
      { kind: "assign", subject: "a", value: "Viewer" },
      { kind: "assign", subject: "a", value: "-viewer" },
    ];
    for (const shape of shapes) {
      expect(refused(() => read(shape))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        status: 400,
        cause: { what: "statement" },
      });
    }
  });

  it("refuses a place that is not canonical and an end that is not a time", () => {
    const base = { kind: "allow", subject: "a", value: "report:read" };
    expect(refused(() => read({ ...base, place: "/org=acme/" }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "place", value: "/org=acme/" },
    });
    for (const expiresAt of [1794528000000, 1.5, -1, "1794528000", null]) {
      expect(refused(() => read({ ...base, expiresAt }))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "time" },
      });
    }
  });

  it("keeps out, silently, a statement that names nothing declared or sits outside the structure", () => {
    expect(read({ kind: "allow", subject: "a", value: "invoice:read" })).toBeUndefined();
    expect(read({ kind: "deny", subject: "a", value: "invoice:*" })).toBeUndefined();
    expect(read({ kind: "exclude", subject: "a", value: "*:delete" })).toBeUndefined();
    expect(
      read({ kind: "allow", subject: "a", value: "report:read", place: "/unit=u7" }),
    ).toBeUndefined();
  });

  it("never drops an assignment for its role, which only its place resolves", () => {
    expect(read({ kind: "assign", subject: "a", value: "deleted" })).toMatchObject({
      value: "deleted",
    });
  });
});

describe("readStatements", () => {
  it("reads in order, leaving inert statements out", () => {
    const rows: Statement[] = [
      { kind: "allow", subject: "a", value: "report:read" },
      { kind: "allow", subject: "a", value: "gone:read" },
      { kind: "assign", subject: "b", value: "viewer", place: "/org=acme" },
    ];
    expect(readStatements(compiled, rows).map((statement) => statement.source)).toEqual([
      rows[0],
      rows[2],
    ]);
  });

  it("refuses a value that is not a list, and any malformed item", () => {
    expect(refused(() => readStatements(compiled, { kind: "allow" }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "statement" },
    });
    expect(
      refused(() =>
        readStatements(compiled, [{ kind: "allow", subject: "a", value: "report:read" }, null]),
      ),
    ).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what: "statement", value: null } });
  });
});

describe("identityOf", () => {
  it("is equal for an absent place and the root, whatever the end", () => {
    const a = identityOf({ kind: "allow", subject: "a", value: "report:read" });
    const b = identityOf({ kind: "allow", subject: "a", value: "report:read", place: "/" });
    expect(a).toBe(b);
    const [stored] = readStatements(compiled, [
      { kind: "allow", subject: "a", value: "report:read", expiresAt: 10 },
    ]);
    expect(identityOf(stored!)).toBe(a);
  });

  it("differs when any of kind, subject, value or place differs", () => {
    const base = { kind: "allow", subject: "a", value: "report:read", place: "/org=a" } as const;
    const identities = new Set([
      identityOf(base),
      identityOf({ ...base, kind: "deny" }),
      identityOf({ ...base, subject: "b" }),
      identityOf({ ...base, value: "report:*" }),
      identityOf({ ...base, place: "/org=b" }),
      identityOf({ ...base, subject: "a,b" }),
    ]);
    expect(identities.size).toBe(6);
  });
});

describe("permanent management", () => {
  const rows: Statement[] = [
    { kind: "allow", subject: "owner", value: "*" },
    { kind: "allow", subject: "deploy", value: "*", place: "/" },
    { kind: "allow", subject: "temp", value: "*", expiresAt: 1794528000 },
    { kind: "allow", subject: "tom", value: "*", place: "/org=acme" },
    { kind: "allow", subject: "ann", value: "report:*" },
    { kind: "deny", subject: "eve", value: "*" },
  ];
  const statements = readStatements(compiled, rows);

  it("is a permanent allow of `*` at the root, and nothing else", () => {
    expect(statements.map(isPermanentManagement)).toEqual([true, true, false, false, false, false]);
  });

  it("makes a permanent manager of its subject, or of every member of its group", () => {
    expect(isPermanentManager(statements, { subject: "owner", groups: [] })).toBe(true);
    expect(isPermanentManager(statements, { subject: "bot", groups: ["deploy"] })).toBe(true);
    expect(permanentManagementOf(statements, { subject: "bot", groups: ["deploy"] })?.source).toBe(
      rows[1],
    );
    for (const subject of ["temp", "tom", "ann", "eve"]) {
      expect(isPermanentManager(statements, { subject, groups: [] })).toBe(false);
    }
  });
});
