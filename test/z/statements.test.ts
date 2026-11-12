import { describe, expect, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
import { readStatement, readStatements } from "../../src/z/_internal/statements.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import type { Statement } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

const catalog = defineCatalog({
  permissions: ["report:read", "report:write", "access:manage"],
  presets: { viewer: ["report:read"] },
  places: { "/": ["org"], "org": ["unit"] },
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
