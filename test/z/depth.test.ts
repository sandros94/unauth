import { describe, expect, it } from "vitest";
import { ask } from "../../src/z/ask.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import { could, issueGrants } from "../../src/z/grants.ts";
import { resolveRole } from "../../src/z/roles.ts";
import type { GrantsPart, Statement, StoredRole } from "../../src/z/types.ts";
import { validateRole } from "../../src/z/validate.ts";
import { refused } from "./_expect.ts";

const DEPTH = 20_000;
const CHAINED = 1_500;
const RINGED = 20_000;
const BOUND_MS = 2_000;
const MONDAY = 1794214800;
const now = () => MONDAY * 1000;

const catalog = defineCatalog({
  permissions: ["doc:read", "doc:write", "chat:send"],
  presets: { viewer: ["doc:read"] },
});

function chain(last: readonly string[], entry = (next: string) => [next]): StoredRole[] {
  return Array.from({ length: DEPTH }, (_, index) => ({
    name: `r${index}`,
    entries: index === DEPTH - 1 ? last : entry(`r${index + 1}`),
  }));
}

function holding(roles: readonly StoredRole[]) {
  return {
    subject: "kim",
    statements: [{ kind: "assign", subject: "kim", value: "r0" }] satisfies Statement[],
    roles,
  };
}

function timed<T>(run: () => T): T {
  const start = performance.now();
  const result = run();
  expect(performance.now() - start).toBeLessThan(BOUND_MS);
  return result;
}

const MODES: [string, GrantsPart[] | undefined][] = [
  ["with copies", undefined],
  ["by name", ["presets"]],
];

describe(`a chain of ${DEPTH} stored roles ending in a permission`, () => {
  const roles = chain(["doc:write", "viewer"]);
  const write = { permission: "doc:write" } as const;

  it("is answered by `ask`, resolved, and validated without a problem", () => {
    timed(() => {
      expect(ask(catalog, holding(roles), write, { now }).allowed).toBe(true);
      expect(resolveRole(catalog, "r0", { roles })).toStrictEqual(["doc:read", "doc:write"]);
      expect(validateRole(catalog, roles[0], { roles })).toStrictEqual([]);
    });
  });

  it.each(MODES)("is carried by grants and read back after a JSON round trip, %s", (_, omit) => {
    timed(() => {
      const grants: unknown = JSON.parse(
        JSON.stringify(issueGrants(catalog, holding(roles), { omit, now })),
      );
      expect(could(catalog, grants, write, { now })).toMatchObject({
        allowed: true,
        by: { kind: "assign", value: "r0" },
      });
      expect(could(catalog, grants, { permission: "doc:read" }, { now }).allowed).toBe(true);
    });
  });
});

describe(`a ring of ${DEPTH} stored roles`, () => {
  const roles = chain(["r0"]);

  it("gives nothing, is reported as a cycle, and is left out of grants", () => {
    timed(() => {
      expect(ask(catalog, holding(roles), { permission: "doc:read" }, { now }).allowed).toBe(false);
      expect(resolveRole(catalog, "r0", { roles })).toStrictEqual([]);
      expect(validateRole(catalog, roles[0], { roles })).toMatchObject([
        {
          code: "ERR_AUTHZ_ROLE_INVALID",
          path: ["entries", 0],
          cause: { role: "r0", reason: "cycle", reference: "r0" },
        },
      ]);
      expect(issueGrants(catalog, holding(roles), { now }).nt).toStrictEqual({});
    });
  });
});

describe(`a chain of ${DEPTH} stored roles whose last reference exists nowhere`, () => {
  const roles = chain(["doc:read", "ghost"]);

  it("gives nothing and is reported as an unknown reference", () => {
    timed(() => {
      expect(resolveRole(catalog, "r0", { roles })).toStrictEqual([]);
      expect(ask(catalog, holding(roles), { permission: "doc:read" }, { now }).allowed).toBe(false);
      expect(validateRole(catalog, roles[0], { roles })).toMatchObject([
        {
          code: "ERR_AUTHZ_ROLE_INVALID",
          path: ["entries", 0],
          cause: { role: "r0", reason: "reference", reference: "ghost" },
        },
      ]);
      expect(issueGrants(catalog, holding(roles), { now }).nt).toStrictEqual({});
    });
  });
});

describe(`a chain of ${DEPTH} stored roles each giving everything but the next`, () => {
  const exceptNext = (next: string) => ["*", `-${next}`];

  it("alternates everything and nothing down an open chain", () => {
    const roles = chain(["*"], exceptNext);
    timed(() => {
      expect(resolveRole(catalog, `r${DEPTH - 1}`, { roles })).toHaveLength(3);
      expect(resolveRole(catalog, "r1", { roles })).toHaveLength(3);
      expect(resolveRole(catalog, "r0", { roles })).toStrictEqual([]);
      expect(ask(catalog, holding(roles), { permission: "chat:send" }, { now }).allowed).toBe(
        false,
      );
      expect(validateRole(catalog, roles[0], { roles })).toStrictEqual([]);
    });
  });

  it("gives nothing in a ring, which is reported as a cycle", () => {
    const roles = chain(["*", "-r0"], exceptNext);
    timed(() => {
      expect(resolveRole(catalog, "r1", { roles })).toStrictEqual([]);
      expect(validateRole(catalog, roles[0], { roles })).toMatchObject([
        { path: ["entries", 1], cause: { role: "r0", reason: "cycle", reference: "r0" } },
      ]);
    });
  });
});

describe(`presets in a chain of ${DEPTH}`, () => {
  const presets = (last: readonly string[]) =>
    Object.fromEntries(
      Array.from({ length: DEPTH }, (_, index) => [
        `p${index}`,
        index === DEPTH - 1 ? last : [`p${index + 1}`],
      ]),
    );

  it("are accepted and resolved", () => {
    const deep = timed(() =>
      defineCatalog({ permissions: ["doc:read", "doc:write"], presets: presets(["doc:write"]) }),
    );
    expect(resolveRole(deep, "p0")).toStrictEqual(["doc:write"]);
  });

  it("are refused in a ring as a short ring is, naming where it closes", () => {
    const short = refused(() =>
      defineCatalog({ permissions: ["doc:read"], presets: { p0: ["p1"], p1: ["p2"], p2: ["p0"] } }),
    );
    expect(short).toMatchObject({
      code: "ERR_AUTHZ_CATALOG_INVALID",
      cause: { reason: "cycle", at: "presets.p2", value: "p0" },
    });
    const ring = timed(() =>
      refused(() => defineCatalog({ permissions: ["doc:read"], presets: presets(["p0"]) })),
    );
    expect(ring).toMatchObject({
      code: "ERR_AUTHZ_CATALOG_INVALID",
      message: short.message,
      cause: { reason: "cycle", at: `presets.p${DEPTH - 1}`, value: "p0" },
    });
  });
});

describe("implications a long way down", () => {
  const linked = (count: number, last: (first: string) => readonly string[]) => {
    const permissions = Array.from({ length: count }, (_, index) => `p${index}:use`);
    const implies = Object.fromEntries(
      permissions.map((permission, index) => [
        permission,
        index === count - 1 ? last(permissions[0]!) : [permissions[index + 1]!],
      ]),
    );
    return { permissions, implies };
  };

  it(`in a chain of ${CHAINED}: an allow of the first gives the last, a deny of the last blocks the first`, () => {
    const data = linked(CHAINED, () => []);
    const first = data.permissions[0]!;
    const last = data.permissions.at(-1)!;
    const deep = timed(() => defineCatalog(data));
    const statements: Statement[] = [{ kind: "allow", subject: "kim", value: first }];
    timed(() => {
      expect(ask(deep, { subject: "kim", statements }, { permission: last }, { now }).allowed).toBe(
        true,
      );
      const denied: Statement[] = [...statements, { kind: "deny", subject: "kim", value: last }];
      expect(
        ask(deep, { subject: "kim", statements: denied }, { permission: first }, { now }).by,
      ).toMatchObject({ kind: "deny", value: last });
    });
  });

  it(`in a ring of ${RINGED} are refused as a short ring is`, () => {
    const short = refused(() =>
      defineCatalog({
        permissions: ["a:x", "a:y", "a:z"],
        implies: { "a:x": ["a:y"], "a:y": ["a:z"], "a:z": ["a:x"] },
      }),
    );
    expect(short).toMatchObject({
      code: "ERR_AUTHZ_CATALOG_INVALID",
      cause: { reason: "cycle", at: "implies", value: "a:x" },
    });
    const data = linked(RINGED, (first) => [first]);
    const ring = timed(() => refused(() => defineCatalog(data)));
    expect(ring).toMatchObject({
      code: "ERR_AUTHZ_CATALOG_INVALID",
      message: short.message,
      cause: { reason: "cycle", at: "implies", value: data.permissions[0] },
    });
  });
});
