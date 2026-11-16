import { describe, expect, expectTypeOf, it } from "vitest";
import { ask } from "../../src/z/ask.ts";
import { type Authz, type PermissionOf, type PresetOf, defineAuthz } from "../../src/z/authz.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import { assertGrants, could, diverged, issueGrants } from "../../src/z/grants.ts";
import type { Catalog } from "../../src/z/catalog.ts";
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
    expect(bound.ps).toStrictEqual({ viewer: [0] });
    const question = { permission: "report:read", place: ACME } as const;
    expect(authz.could(bound, question, { now })).toEqual(
      could(authz.catalog, bound, question, { now }),
    );
    expect(authz.could(bound, question, { now })).toMatchObject({
      allowed: true,
      covered: true,
      by: { kind: "assign", value: "viewer", place: ACME },
    });
    expect(authz.could(bound, { ...question, permission: "report:write" }, { now })).toEqual({
      allowed: false,
      covered: true,
    });
    const scoped = authz.issueGrants(ana, { bases: [ACME], now });
    const elsewhere = { permission: "report:read", place: "/org=globex" } as const;
    expect(authz.could(scoped, elsewhere, { now })).toEqual({ allowed: false, covered: false });
  });

  it("issues presets by name by default when defined so, and lets a call replace the default", () => {
    const named = defineAuthz(authz.catalog.data, { omit: ["presets"] });
    const byDefault = named.issueGrants(ana, { now });
    expect(byDefault).not.toHaveProperty("ps");
    expect(byDefault).toEqual(issueGrants(named.catalog, ana, { omit: ["presets"], now }));
    expect(named.issueGrants(ana, { omit: [], now }).ps).toStrictEqual({ viewer: [0] });
    expect(named.issueGrants(ana, { omit: undefined, now })).not.toHaveProperty("ps");
    expect(authz.issueGrants(ana, { omit: ["presets"], now })).not.toHaveProperty("ps");
  });

  it("takes a catalog already defined, the very object, so that one catalog serves several places", () => {
    const catalog = defineCatalog({
      permissions: ["report:read", "report:write"],
      presets: { viewer: ["report:read"] },
    });
    const bound = defineAuthz(catalog, { omit: ["presets"] });
    expect(bound.catalog).toBe(catalog);
    expectTypeOf(bound).toEqualTypeOf<Authz<"report:read" | "report:write", "viewer">>();
    const read = {
      subject: "ana",
      statements: [{ kind: "assign", subject: "ana", value: "viewer" }],
    } as const;
    const question = { permission: "report:read" } as const;
    expect(bound.ask(read, question, { now })).toEqual(ask(catalog, read, question, { now }));
    expect(bound.issueGrants(read, { now })).not.toHaveProperty("ps");
    expect(defineAuthz(catalog).issueGrants(read, { now })).toHaveProperty("ps");
  });

  it("refuses a catalog whose fingerprint is not the one its data gives, when it is defined", () => {
    const loaded = { data: authz.catalog.data, fingerprint: "AAAAAAAAAAA.AAAAAAAAAAA" };
    expect(refused(() => defineAuthz(loaded))).toMatchObject({
      code: "ERR_AUTHZ_CATALOG_INVALID",
      cause: { reason: "fingerprint" },
    });
    const copied = { data: authz.catalog.data, fingerprint: authz.catalog.fingerprint };
    expect(defineAuthz(copied).catalog).toBe(copied);
  });

  it.each([
    ["`null`", null],
    ["a string", "report:read"],
    ["a number", 7],
    ["`undefined`", undefined],
  ])("refuses %s as a catalog, as `defineCatalog` does", (_, value) => {
    const expected = { code: "ERR_AUTHZ_CATALOG_INVALID", status: 500 };
    expect(refused(() => defineCatalog(value as never))).toMatchObject(expected);
    expect(refused(() => defineAuthz(value as never))).toMatchObject(expected);
  });

  it("tells what has diverged as the function does, and reads in `could` grants by name with its own presets", () => {
    const older = defineAuthz({
      ...authz.catalog.data,
      presets: { viewer: ["report:write"], owner: ["*"] },
    });
    const copied = older.issueGrants(ana, { now });
    const told = { segments: ["presets"], permissions: [], presets: ["viewer"] };
    expect(authz.diverged(copied, { now })).toStrictEqual(told);
    expect(diverged(authz.catalog, copied, { now })).toStrictEqual(told);
    expect(authz.diverged(authz.issueGrants(ana, { now }), { now })).toBeUndefined();
    expect(authz.could(copied, { permission: "report:write", place: ACME }, { now })).toMatchObject(
      {
        allowed: true,
        diverged: told,
      },
    );
    const named = older.issueGrants(ana, { omit: ["presets"], now });
    const write = { permission: "report:write", place: ACME } as const;
    expect(authz.could(named, write, { now })).toStrictEqual({
      allowed: false,
      covered: true,
      diverged: { segments: ["presets"], permissions: [], presets: [] },
    });
    expect(authz.could(named, write, { now })).toStrictEqual(
      could(authz.catalog, named, write, { now }),
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
      "catalog",
      "could",
      "diverged",
      "issueGrants",
      "placeFits",
      "relatedValues",
      "resolveRole",
      "rolesOf",
      "validateRole",
      "validateStatement",
    ]);
  });

  it("names the permissions and presets of a catalog or an engine as types, and nothing of anything else", () => {
    const catalog = defineCatalog({
      permissions: ["report:read", "report:write"],
      presets: { viewer: ["report:read"] },
    });
    expectTypeOf<PermissionOf<typeof catalog>>().toEqualTypeOf<"report:read" | "report:write">();
    expectTypeOf<PresetOf<typeof catalog>>().toEqualTypeOf<"viewer">();
    expectTypeOf<PermissionOf<typeof authz>>().toEqualTypeOf<
      "report:read" | "report:write" | "access:manage"
    >();
    expectTypeOf<PresetOf<typeof authz>>().toEqualTypeOf<"viewer" | "owner">();
    const bound = defineAuthz(catalog);
    expectTypeOf<PermissionOf<typeof bound>>().toEqualTypeOf<"report:read" | "report:write">();
    expectTypeOf<PresetOf<typeof bound>>().toEqualTypeOf<"viewer">();
    const plain = defineCatalog({ permissions: ["report:read"] });
    expectTypeOf<PermissionOf<typeof plain>>().toEqualTypeOf<"report:read">();
    expectTypeOf<PresetOf<typeof plain>>().toEqualTypeOf<never>();
    expectTypeOf<PermissionOf<Catalog>>().toEqualTypeOf<string>();
    expectTypeOf<PermissionOf<Authz>>().toEqualTypeOf<string>();
    // @ts-expect-error catalog data is not a catalog
    expectTypeOf<PermissionOf<{ permissions: ["report:read"] }>>();
    // @ts-expect-error a string is neither a catalog nor an engine
    expectTypeOf<PresetOf<string>>();
    // @ts-expect-error the data of a catalog is not the catalog
    expectTypeOf<PermissionOf<typeof catalog.data>>();
    // @ts-expect-error the data of a catalog is not the catalog
    expectTypeOf<PresetOf<typeof catalog.data>>();
  });

  it("keeps the permissions of its catalog as types", () => {
    const grants = authz.issueGrants(ana, { now });
    // @ts-expect-error "report:raed" is not a permission of this catalog
    expect(refused(() => authz.could(grants, { permission: "report:raed" })).code).toBe(
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
