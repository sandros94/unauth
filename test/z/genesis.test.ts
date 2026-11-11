import { describe, expect, it } from "vitest";
import { type Catalog, defineCatalog } from "../../src/z/catalog.ts";
import { checkGenesis } from "../../src/z/change.ts";
import type { Statement } from "../../src/z/types.ts";
import { ACME, DAY, NOW, allow, assign, deny, exclude, forge } from "./_change-world.ts";
import { refused } from "./_expect.ts";

const now = (): number => NOW * 1000;

function genesis(statement: unknown, managers: unknown, catalog: Catalog = forge): void {
  checkGenesis(catalog, statement as Statement, { managers: managers as Statement[], now });
}

function reasons(statement: Statement, managers: Statement[], catalog: Catalog = forge): unknown {
  const error = refused(() => genesis(statement, managers, catalog));
  expect(error.code).toBe("ERR_AUTHZ_CHANGE_REFUSED");
  expect(error.status).toBe(403);
  return error.cause;
}

describe("checkGenesis", () => {
  it("accepts the first permanent manager while the root holds none, about anyone", () => {
    for (const subject of ["ed", "deploy", "admins"]) {
      expect(() => genesis(allow(subject, "*"), [])).not.toThrow();
    }
    expect(() => genesis(allow("ed", "*", "/"), [])).not.toThrow();
  });

  it("counts only the permanent allows of `*` at the root among what is handed in", () => {
    const managers = [
      allow("ops", "*", "/", NOW + DAY),
      allow("tom", "*", ACME),
      allow("ann", "report:read"),
      deny("eve", "*"),
    ];
    expect(() => genesis(allow("ed", "*"), managers)).not.toThrow();
  });

  it("is refused with `not-first` once the root holds a permanent manager", () => {
    expect(reasons(allow("mallory", "*"), [allow("ed", "*")])).toEqual({ reasons: ["not-first"] });
    expect(reasons(allow("ed", "*"), [allow("ed", "*")])).toEqual({ reasons: ["not-first"] });
    expect(reasons(allow("eve", "*"), [allow("admins", "*")])).toEqual({ reasons: ["not-first"] });
  });

  it("is refused with `not-manager` by a catalog that designates no manager permission", () => {
    const flat = defineCatalog({ permissions: ["post:read", "post:publish"] });
    expect(reasons(allow("ed", "*"), [], flat)).toEqual({ reasons: ["not-manager"] });
    expect(reasons(allow("ed", "*"), [allow("ed", "*")], flat)).toEqual({
      reasons: ["not-manager", "not-first"],
    });
  });

  it("refuses as malformed a statement that is not a permanent allow of `*` at the root", () => {
    const cases: unknown[] = [
      allow("ed", "*", "/", NOW + DAY),
      allow("ed", "report:*"),
      allow("ed", "report:read"),
      allow("ed", "*:*"),
      allow("ed", "*", ACME),
      allow("ed", "*", "/org=acme/"),
      deny("ed", "*"),
      exclude("ed", "*"),
      assign("ed", "owner"),
      allow("", "*"),
      { kind: "allow", subject: 7, value: "*" },
      { kind: "allow", value: "*" },
      null,
      "ed",
    ];
    for (const statement of cases) {
      const error = refused(() => genesis(statement, []));
      expect([statement, error.code, error.cause]).toEqual([
        statement,
        "ERR_AUTHZ_MALFORMED",
        { what: "statement", value: statement },
      ]);
    }
  });

  it("refuses as malformed permanent managers that are not a list of statements", () => {
    for (const managers of [undefined, null, "root", allow("root", "*"), [{ kind: "grant" }]]) {
      const error = refused(() => genesis(allow("ed", "*"), managers));
      expect([managers, error.code]).toEqual([managers, "ERR_AUTHZ_MALFORMED"]);
    }
  });

  it("refuses the input before any rule", () => {
    expect(refused(() => genesis(allow("ed", "*", ACME), [allow("ed", "*")])).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
  });
});
