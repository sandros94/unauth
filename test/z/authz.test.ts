import { describe, expect, expectTypeOf, it } from "vitest";
import { ask } from "../../src/z/ask.ts";
import { defineAuthz } from "../../src/z/authz.ts";
import { assertGrants, can, could, issueGrants } from "../../src/z/grants.ts";
import type { Grants, Statement } from "../../src/z/types.ts";
import { validateRole, validateStatement } from "../../src/z/validate.ts";
import { refused } from "./_expect.ts";

const authz = defineAuthz({
  permissions: ["report:read", "report:write", "access:manage"],
  implies: { "report:write": ["report:read"] },
  presets: { viewer: ["report:read"], owner: ["*"] },
  places: { "/": ["org"] },
});

const NOW = 1_794_214_800;
const now = (): number => NOW * 1000;
const ACME = "/org=acme";

const root: Statement = { kind: "allow", subject: "ed", value: "*" };
const viewer: Statement = { kind: "assign", subject: "ana", value: "viewer", place: ACME };
const ana = { subject: "ana", statements: [viewer] };

describe("the engine bound to its catalog", () => {
  it("answers as the function given the same catalog does", () => {
    const question = { permission: "report:read", place: ACME } as const;
    const bound = authz.ask(ana, question, { now });
    expect(bound).toEqual(ask(authz.catalog, ana, question, { now }));
    expect(bound).toStrictEqual({ allowed: true, covered: true, by: viewer });
    expect(authz.ask(ana, { ...question, permission: "report:write" }, { now }).allowed).toBe(
      false,
    );
  });

  it("names the statement handed in, typed as the application's own", () => {
    type Row = Statement & { id: number };
    const rows: Row[] = [{ ...viewer, id: 7 }];
    const decision = authz.ask(
      { subject: "ana", statements: rows },
      { permission: "report:read", place: ACME },
    );
    expect(decision.by).toBe(rows[0]);
    expectTypeOf(decision.by).toEqualTypeOf<Row | undefined>();
  });

  it("issues grants the functions read, and reads grants the functions issue", () => {
    const bound = authz.issueGrants(ana, { now });
    expect(bound).toEqual(issueGrants(authz.catalog, ana, { now }));
    const question = { permission: "report:read", place: ACME } as const;
    expect(can(authz.catalog, bound, question, { now })).toBe(true);
    expect(authz.can(bound, question, { now })).toBe(true);
    expect(authz.can(bound, { ...question, permission: "report:write" }, { now })).toBe(false);
    expect(authz.could(bound, question, { now })).toEqual(
      could(authz.catalog, bound, question, { now }),
    );
  });

  it("gives the whole answer with `could` where `can` gives a boolean", () => {
    const whole = authz.issueGrants(ana, { now });
    expect(authz.could(whole, { permission: "report:read", place: ACME }, { now })).toMatchObject({
      allowed: true,
      covered: true,
      by: { kind: "assign", value: "viewer", place: ACME },
    });
    expect(authz.could(whole, { permission: "report:write", place: ACME }, { now })).toEqual({
      allowed: false,
      covered: true,
    });
    const scoped = authz.issueGrants(ana, { bases: [ACME], now });
    const elsewhere = { permission: "report:read", place: "/org=globex" } as const;
    expect(authz.could(scoped, elsewhere, { now })).toEqual({ allowed: false, covered: false });
    expect(authz.can(scoped, elsewhere, { now })).toBe(false);
  });

  it("answers `can` false and refuses in `could` for grants issued under another catalog", () => {
    const older = defineAuthz({ permissions: ["report:read", "access:manage"] });
    const stale = older.issueGrants({ subject: "ana", statements: [] }, { now });
    expect(authz.can(stale, { permission: "report:read" }, { now })).toBe(false);
    expect(refused(() => authz.could(stale, { permission: "report:read" }, { now })).code).toBe(
      "ERR_AUTHZ_GRANTS_CATALOG",
    );
  });

  it("validates a statement as the function does", () => {
    const statement = { kind: "assign", subject: "bo", value: "desk", place: ACME } as const;
    const roles = [{ name: "desk", entries: ["viewer"] }];
    expect(authz.validateStatement(statement, { roles })).toStrictEqual([]);
    const bound = authz.validateStatement(statement);
    expect(bound).toEqual(validateStatement(authz.catalog, statement));
    expect(bound.map(({ code }) => code)).toStrictEqual(["ERR_AUTHZ_ROLE_INVALID"]);
    expect(authz.validateStatement(root)).toStrictEqual([]);
  });

  it("validates a statement against its clock as the function does", () => {
    const ended = { kind: "allow", subject: "bo", value: "report:read", expiresAt: NOW } as const;
    const bound = authz.validateStatement(ended, { now });
    expect(bound).toEqual(validateStatement(authz.catalog, ended, { now }));
    expect(bound).toMatchObject([
      { code: "ERR_AUTHZ_STATEMENT_ENDED", path: ["expiresAt"], cause: { expiresAt: NOW } },
    ]);
    expect(authz.validateStatement({ ...ended, expiresAt: NOW + 1 }, { now })).toStrictEqual([]);
  });

  it("validates a stored role as the function does", () => {
    const role = { name: "desk", entries: ["viewer", "-report:raed"] };
    const bound = authz.validateRole(role);
    expect(bound).toEqual(validateRole(authz.catalog, role));
    expect(bound).toMatchObject([{ code: "ERR_AUTHZ_PERMISSION_UNKNOWN", path: ["entries", 1] }]);
    expect(authz.validateRole({ name: "desk", entries: ["viewer"] })).toStrictEqual([]);
  });

  it("resolves roles, names related values and checks places against its catalog", () => {
    expect(authz.resolveRole("viewer")).toEqual(["report:read"]);
    expect(authz.relatedValues("report:write").presets).toEqual(["owner"]);
    expect(authz.placeFits(ACME)).toBe(true);
    expect(authz.placeFits("/unit=u7")).toBe(false);
  });

  it("binds the questions and validation, and no function of the past", () => {
    expect(Object.keys(authz).toSorted()).toStrictEqual([
      "ask",
      "can",
      "catalog",
      "could",
      "issueGrants",
      "placeFits",
      "relatedValues",
      "resolveRole",
      "validateRole",
      "validateStatement",
    ]);
  });

  it("keeps the permissions of its catalog as types", () => {
    const grants = authz.issueGrants(ana, { now });
    // @ts-expect-error "report:raed" is not a permission of this catalog
    expect(refused(() => authz.can(grants, { permission: "report:raed" })).code).toBe(
      "ERR_AUTHZ_PERMISSION_UNKNOWN",
    );
  });

  it("leaves typing a value as grants to the function, given its catalog", () => {
    const issued: unknown = authz.issueGrants(ana, { now });
    assertGrants(authz.catalog, issued, { now });
    const typed: Grants = issued;
    expect(typed.ct).toBe(authz.catalog.fingerprint);
  });
});
