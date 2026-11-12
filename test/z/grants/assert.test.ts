import { describe, expect, expectTypeOf, it } from "vitest";
import { defineCatalog } from "../../../src/z/catalog.ts";
import { assertGrants, could, issueGrants } from "../../../src/z/grants.ts";
import type { Grants } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

const MONDAY = 1794214800;
const ACME = "/org=acme";
const now = (): number => MONDAY * 1000;

const catalog = defineCatalog({
  permissions: ["report:read", "report:write", "access:manage"],
  implies: { "report:write": ["report:read"] },
  places: { "/": ["org"] },
});
const other = defineCatalog({
  permissions: ["report:read", "access:manage"],
  presets: { viewer: ["report:read"] },
});

const issued = issueGrants(
  catalog,
  {
    subject: "ann",
    statements: [{ kind: "allow", subject: "ann", value: "report:write", place: ACME }],
  },
  { now },
);

function carried(grants: unknown = issued): unknown {
  const payload: unknown = JSON.parse(JSON.stringify({ sub: "ann", grants }));
  return typeof payload === "object" && payload !== null && "grants" in payload
    ? payload.grants
    : undefined;
}

describe("grants handed over as a carrier holds them", () => {
  it("are read by `could` typed `unknown`", () => {
    const payload = carried();
    expect(could(catalog, payload, { permission: "report:read", place: ACME }, { now })).toEqual({
      allowed: true,
      covered: true,
      by: { kind: "allow", value: "report:write", place: ACME },
    });
    expect(could(catalog, payload, { permission: "report:write" }, { now }).allowed).toBe(false);
    const list: unknown = [payload, carried()];
    expect(could(catalog, list, { permission: "report:read", place: ACME }, { now }).allowed).toBe(
      true,
    );
  });

  it("are still checked whole before any read", () => {
    const broken = carried({ ...issued, nt: [] });
    const question = { permission: "report:read" } as const;
    expect(refused(() => could(catalog, broken, question, { now })).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
    expect(refused(() => could(catalog, "grants", question, { now })).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
  });
});

describe("assertGrants", () => {
  it("types the value as grants, with no cast", () => {
    const payload = carried();
    assertGrants(catalog, payload, { now });
    expectTypeOf(payload).toEqualTypeOf<Grants>();
    const typed: Grants = payload;
    expect(typed.pl).toEqual([ACME]);
    expect(typed.ct).toBe(catalog.fingerprint);
  });

  it("throws `ERR_AUTHZ_MALFORMED` for what is not one set of grants", () => {
    const values: unknown[] = [
      null,
      "grants",
      7,
      {},
      [],
      [issued],
      { ...issued, nt: [] },
      { ...issued, at: MONDAY * 1000 },
      { ...issued, pl: ["/org=acme/"] },
      { ...issued, nt: { "Report:Delete": { a: [[]] } } },
      { ...issued, ct: "other" },
    ];
    for (const value of values) {
      expect([value, refused(() => assertGrants(catalog, value, { now })).code]).toEqual([
        value,
        "ERR_AUTHZ_MALFORMED",
      ]);
    }
  });

  it("throws `ERR_AUTHZ_GRANTS_FORMAT` for another format revision", () => {
    expect(refused(() => assertGrants(catalog, { ...issued, v: "2" }, { now })).code).toBe(
      "ERR_AUTHZ_GRANTS_FORMAT",
    );
  });

  it("throws `ERR_AUTHZ_GRANTS_CATALOG` for grants naming a preset by name, issued under other presets", () => {
    const stale = issueGrants(
      other,
      { subject: "ann", statements: [{ kind: "assign", subject: "ann", value: "viewer" }] },
      { omit: ["presets"], now },
    );
    expect(refused(() => assertGrants(catalog, carried(stale), { now })).code).toBe(
      "ERR_AUTHZ_GRANTS_CATALOG",
    );
  });

  it("throws `ERR_AUTHZ_GRANTS_EARLY` when the clock reads before their issue", () => {
    expect(
      refused(() => assertGrants(catalog, carried(), { now: () => (MONDAY - 1) * 1000 })).code,
    ).toBe("ERR_AUTHZ_GRANTS_EARLY");
    expect(() => assertGrants(catalog, carried(), { now })).not.toThrow();
  });

  it("refuses with the code a read refuses with, for every set a read refuses", () => {
    const sets: unknown[] = [
      { ...issued, v: 1 },
      { ...issued, v: "2", nt: [] },
      { ...issued, ct: "other", nt: [] },
      { ...issued, ct: 7 },
      { ...issued, ct: `${issued.ct.slice(0, 12)}AAAAAAAAAAA`, nt: { viewer: { a: [[]] } } },
      { ...issued, nt: { "report:read": { a: [[0]], z: [] } } },
      { ...issued, nt: { "report:read": { a: [[1]] } } },
      { ...issued, nt: { "report:read": { a: [[null, null, 0]] } } },
      { ...issued, nt: { "report:read": { d: [[null, null, 1]] } } },
    ];
    for (const set of sets) {
      const read = refused(() => could(catalog, set, { permission: "report:read" }, { now }));
      const asserted = refused(() => assertGrants(catalog, set, { now }));
      expect([set, asserted.code, asserted.cause]).toEqual([set, read.code, read.cause]);
    }
  });
});
