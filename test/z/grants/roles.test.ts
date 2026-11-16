import { describe, expect, expectTypeOf, it } from "vitest";
import { defineAuthz } from "../../../src/z/authz.ts";
import { type Catalog, defineCatalog } from "../../../src/z/catalog.ts";
import { type RolesOfOptions, issueGrants, rolesOf } from "../../../src/z/grants.ts";
import type { Question, Statement, StoredRole } from "../../../src/z/types.ts";
import { refused } from "../_expect.ts";

const MONDAY = 1794214800;
const END = MONDAY + 3600;
const now = (): number => MONDAY * 1000;
const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";
const GLOBEX = "/org=globex";

const catalog = defineCatalog({
  permissions: ["report:read", "report:write", "chat:read"],
  presets: { viewer: ["report:read"], editor: ["viewer", "report:write"] },
  places: { "/": ["org"], "org": ["area"] },
});
const roles: StoredRole[] = [{ name: "desk", entries: ["viewer", "chat:read"] }];

function issue(statements: Statement[], options?: { bases?: string[]; omit?: ["presets"] }) {
  return issueGrants(catalog, { subject: "ann", statements, roles }, { ...options, now });
}

function held(grants: unknown, place?: string, at = MONDAY) {
  return rolesOf(catalog, grants, place === undefined ? undefined : { place }, {
    now: () => at * 1000,
  });
}

const viewer: Statement = { kind: "assign", subject: "ann", value: "viewer" };

describe("rolesOf: the names of the roles held at the place asked", () => {
  it("lists the roles of a flat application, asked with no place", () => {
    const flat = defineCatalog({
      permissions: ["report:read", "report:write"],
      presets: { viewer: ["report:read"], editor: ["viewer", "report:write"] },
    });
    const grants = issueGrants(
      flat,
      { subject: "ann", statements: [{ ...viewer, value: "editor" }] },
      { now },
    );
    expect(rolesOf(flat, grants, undefined, { now })).toStrictEqual(["editor"]);
    expect(rolesOf(flat, grants, {}, { now })).toStrictEqual(["editor"]);
    expectTypeOf(rolesOf(flat, grants)).toEqualTypeOf<string[]>();
  });

  it("finds a preset copied or by name", () => {
    expect(held(issue([viewer]))).toStrictEqual(["viewer"]);
    expect(held(issue([viewer], { omit: ["presets"] }))).toStrictEqual(["viewer"]);
    expect(issue([viewer], { omit: ["presets"] })).not.toHaveProperty("ps");
  });

  it("lists a stored role beside a preset, sorted by bytes, each name once", () => {
    const grants = issue([
      viewer,
      { kind: "assign", subject: "team", value: "viewer", expiresAt: END },
      { kind: "assign", subject: "ann", value: "desk" },
      { kind: "assign", subject: "ann", value: "desk", place: ACME },
      { kind: "allow", subject: "ann", value: "chat:read" },
    ]);
    expect(held(grants, ACME)).toStrictEqual(["desk", "viewer"]);
  });

  it("holds a role assigned at a place there and under it, never above it or elsewhere", () => {
    const grants = issue([{ kind: "assign", subject: "ann", value: "editor", place: ACME }]);
    expect(held(grants, ACME)).toStrictEqual(["editor"]);
    expect(held(grants, ARCHIVES)).toStrictEqual(["editor"]);
    expect(held(grants)).toStrictEqual([]);
    expect(held(grants, "/")).toStrictEqual([]);
    expect(held(grants, GLOBEX)).toStrictEqual([]);
  });

  it("leaves out an assignment that has ended", () => {
    const grants = issue([{ ...viewer, expiresAt: MONDAY + 100 }]);
    expect(held(grants, undefined, MONDAY + 99)).toStrictEqual(["viewer"]);
    expect(held(grants, undefined, MONDAY + 100)).toStrictEqual([]);
  });

  it("counts an assignment that ended less than the clock tolerance ago", () => {
    const grants = issue([{ ...viewer, expiresAt: MONDAY + 100 }]);
    const options = (at: number, clockTolerance: number): RolesOfOptions => ({
      now: () => at * 1000,
      clockTolerance,
    });
    expect(rolesOf(catalog, grants, undefined, options(MONDAY + 105, 10))).toStrictEqual([
      "viewer",
    ]);
    expect(rolesOf(catalog, grants, undefined, options(MONDAY + 110, 10))).toStrictEqual([]);
  });

  it("reads several sets, each only where its bases cover the place", () => {
    const acme = issue([viewer, { kind: "assign", subject: "ann", value: "editor", place: ACME }], {
      bases: [ACME],
    });
    const globex = issue([{ kind: "assign", subject: "ann", value: "desk", place: GLOBEX }], {
      bases: [GLOBEX],
    });
    expect(held([acme, globex], ARCHIVES)).toStrictEqual(["editor", "viewer"]);
    expect(held([acme, globex], GLOBEX)).toStrictEqual(["desk"]);
    expect(held([acme, acme], ACME)).toStrictEqual(held(acme, ACME));
  });

  it("gives nothing where no set covers the place", () => {
    const acme = issue([viewer], { bases: [ACME] });
    expect(held(acme)).toStrictEqual([]);
    expect(held(acme, GLOBEX)).toStrictEqual([]);
    expect(held([])).toStrictEqual([]);
  });

  it("lists assigned names only, never a role a held role references", () => {
    const grants = issue([{ kind: "assign", subject: "ann", value: "editor" }]);
    expect(held(grants)).toStrictEqual(["editor"]);
    expect(held(issue([{ ...viewer, value: "desk" }]))).toStrictEqual(["desk"]);
  });

  it("finds roles under another catalog as a read finds them: a copy, a stored role, the presets in force", () => {
    const both = [viewer, { ...viewer, value: "desk" }];
    const names = (catalogIn: Catalog, grants: unknown) =>
      rolesOf(catalogIn, grants, undefined, { now });
    const without = defineCatalog({ permissions: ["report:read", "chat:read"] });
    expect(names(without, issue(both))).toStrictEqual(["desk", "viewer"]);
    expect(names(without, issue(both, { omit: ["presets"] }))).toStrictEqual(["desk"]);
    const renamed = defineCatalog({
      permissions: ["report:read", "chat:read"],
      presets: { viewer: ["chat:read"] },
    });
    expect(names(renamed, issue(both, { omit: ["presets"] }))).toStrictEqual(["desk", "viewer"]);
  });

  it("does not list a role named in `nt` that is in no table and not a preset", () => {
    const grants = issue([viewer], { omit: ["presets"] });
    const ghost = { ...grants, nt: { ...grants.nt, ghost: { a: [[]] } } };
    expect(held(ghost)).toStrictEqual(["viewer"]);
  });

  it("reads no definition and no entry it does not look up", () => {
    const grants = issue([viewer, { ...viewer, value: "desk" }]);
    const broken = {
      ...grants,
      ps: { viewer: 7 },
      sr: { desk: [{}] },
      nt: { ...grants.nt, "report:write": 7, "Not A Name": 7 },
    };
    expect(held(broken)).toStrictEqual(["desk", "viewer"]);
  });

  it("compares the place an item points at as `pl` holds it: another spelling holds nothing", () => {
    const grants = issue([viewer]);
    const spelled = { ...grants, pl: ["/org=acme/"], nt: { viewer: { a: [[0]] } } };
    expect(held(spelled, ACME)).toStrictEqual([]);
  });

  it("takes a full question and does not read its permission", () => {
    const grants = issue([{ kind: "assign", subject: "ann", value: "editor", place: ACME }]);
    const question: Question = { permission: "report:read", place: ARCHIVES };
    expect(rolesOf(catalog, grants, question, { now })).toStrictEqual(["editor"]);
    const unknown = { permission: "not:declared", place: ACME } as Question;
    expect(rolesOf(catalog, grants, unknown, { now })).toStrictEqual(["editor"]);
  });

  it("refuses a question that is not an object", () => {
    const grants = issue([viewer]);
    for (const question of [null, "/org=acme", 7, true]) {
      expect(
        refused(() => rolesOf(catalog, grants, question as Pick<Question, "place">, { now })),
      ).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "question", value: question },
      });
    }
  });

  it("refuses a place as the place of a question is refused", () => {
    const grants = issue([viewer]);
    for (const place of ["/org=acme/", "org=acme", "", 7, null]) {
      expect(
        refused(() => rolesOf(catalog, grants, { place } as Pick<Question, "place">, { now })),
      ).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what: "place", value: place } });
    }
    expect(refused(() => held(grants, "/unit=u7"))).toMatchObject({
      code: "ERR_AUTHZ_PLACE_OUTSIDE",
      cause: { place: "/unit=u7" },
    });
  });

  it("checks the question before the grants", () => {
    expect(refused(() => held(null, "/unit=u7"))).toMatchObject({
      code: "ERR_AUTHZ_PLACE_OUTSIDE",
    });
  });

  it("refuses as a read refuses: another format, issued in the future, malformed", () => {
    const grants = issue([viewer]);
    expect(refused(() => held({ ...grants, v: "2" }))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FORMAT",
    });
    expect(refused(() => held(grants, undefined, MONDAY - 1))).toMatchObject({
      code: "ERR_AUTHZ_GRANTS_FUTURE",
    });
    expect(
      refused(() => rolesOf(catalog, grants, undefined, { now, clockTolerance: -1 })),
    ).toMatchObject({ code: "ERR_UNAUTH_CONFIG_INVALID" });
    for (const set of [
      null,
      { ...grants, ct: "x" },
      { ...grants, nt: [] },
      { ...grants, ps: [] },
      { ...grants, nt: { viewer: 7 } },
      { ...grants, nt: { viewer: { a: [[0]] } } },
      { ...grants, nt: { viewer: { d: [[]] } } },
      { ...grants, nt: { viewer: { a: 7 } } },
      { ...grants, nt: { viewer: { a: [[null, MONDAY * 1000]] } } },
      { ...grants, nt: { viewer: { a: [[], 7] } } },
      { ...grants, pl: [7], nt: { viewer: { a: [[0]] } } },
      { ...grants, pl: [null], nt: { viewer: { a: [[0]] } } },
    ]) {
      expect(refused(() => held(set))).toMatchObject({
        code: "ERR_AUTHZ_MALFORMED",
        cause: { what: "grants" },
      });
    }
  });

  it("refuses an entry under a role name in a set that does not cover the place only once it is read", () => {
    const acme = issue([viewer], { bases: [ACME] });
    const broken = { ...acme, nt: { viewer: 7 } };
    expect(held(broken, GLOBEX)).toStrictEqual([]);
    expect(refused(() => held(broken, ACME))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "grants" },
    });
  });

  it("is bound on the engine as `rolesOf(grants, question?, options?)`", () => {
    const authz = defineAuthz(catalog);
    const grants = issue([{ kind: "assign", subject: "ann", value: "editor", place: ACME }]);
    expect(authz.rolesOf(grants, { place: ARCHIVES }, { now })).toStrictEqual(
      rolesOf(catalog, grants, { place: ARCHIVES }, { now }),
    );
    expect(authz.rolesOf(grants, { place: ARCHIVES }, { now })).toStrictEqual(["editor"]);
    expect(authz.rolesOf(grants, undefined, { now })).toStrictEqual([]);
    expectTypeOf<Parameters<typeof authz.rolesOf>[1]>().toEqualTypeOf<
      Pick<Question, "place"> | undefined
    >();
    expectTypeOf<Parameters<typeof authz.rolesOf>[2]>().toEqualTypeOf<RolesOfOptions | undefined>();
  });
});
