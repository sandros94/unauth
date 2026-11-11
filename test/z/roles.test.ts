import { describe, expect, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
import { checkRoleDefinition } from "../../src/z/_internal/role-definition.ts";
import { NO_ROLE, roleReader } from "../../src/z/_internal/roles.ts";
import { defineCatalog } from "../../src/z/catalog.ts";
import { resolveRole } from "../../src/z/roles.ts";
import type { StoredRole } from "../../src/z/types.ts";
import { refused } from "./_expect.ts";

const catalog = defineCatalog({
  permissions: [
    "report:list",
    "report:read",
    "report:write",
    "billing:read",
    "billing:write",
    "chat:read",
    "chat:send",
    "chat:kick",
    "access:manage",
  ],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  presets: {
    support: ["*:read", "-billing:read"],
    moderator: ["chat:*", "billing:read"],
    owner: ["*"],
    ops: ["chat:*", "access:manage"],
    lead: ["owner", "-ops"],
    plain: ["*", "-report:read"],
    viewer: ["report:read"],
  },
  places: { "/": ["org"], "org": ["unit"], "*": ["folder"] },
  manager: "access:manage",
});
const compiled = compiledOf(catalog);

const role = (name: string, entries: string[], home?: string): StoredRole =>
  home === undefined ? { name, entries } : { name, home, entries };

describe("presets", () => {
  it("resolve wildcards, exclusions and references as the model's examples do", () => {
    expect(resolveRole(catalog, "support")).toEqual(["chat:read", "report:read"]);
    expect(resolveRole(catalog, "lead")).toEqual([
      "billing:read",
      "billing:write",
      "report:list",
      "report:read",
      "report:write",
    ]);
  });

  it("take out what implies an excluded permission", () => {
    expect(resolveRole(catalog, "plain")).toEqual([
      "access:manage",
      "billing:read",
      "billing:write",
      "chat:kick",
      "chat:read",
      "chat:send",
      "report:list",
    ]);
  });

  it("take out what implies a permission of an excluded role, as for an excluded permission", () => {
    const auditing = defineCatalog({
      permissions: ["report:list", "report:read", "report:write"],
      implies: { "report:write": ["report:read"] },
      presets: { auditor: ["report:read"], clerk: ["report:*", "-auditor"] },
    });
    expect(resolveRole(auditing, "clerk")).toEqual(["report:list"]);
    const stored: StoredRole[] = [{ name: "desk", entries: ["report:*", "-auditor"] }];
    expect(resolveRole(auditing, "desk", { roles: stored })).toEqual(["report:list"]);
  });

  it("keep a referenced role's exclusions unless the referencing role names the permission", () => {
    const local = defineCatalog({
      permissions: ["billing:read", "report:read", "chat:send"],
      presets: {
        support: ["*:read", "-billing:read"],
        moderator: ["chat:send", "billing:read"],
        billing: ["support", "billing:read"],
        mixed: ["support", "moderator"],
        wide: ["support", "billing:*"],
        again: ["mixed", "*"],
      },
    });
    expect(resolveRole(local, "billing")).toEqual(["billing:read", "report:read"]);
    expect(resolveRole(local, "mixed")).toEqual(["chat:send", "report:read"]);
    expect(resolveRole(local, "wide")).toEqual(["billing:read", "report:read"]);
    expect(resolveRole(local, "again")).toEqual(["billing:read", "chat:send", "report:read"]);
  });

  it("refuse a name that is neither a preset nor a stored role visible at the place", () => {
    expect(refused(() => resolveRole(catalog, "ghost"))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      status: 400,
      cause: { role: "ghost", reason: "unknown" },
    });
    expect(refused(() => resolveRole(catalog, "support", { at: "/unit=u" }))).toMatchObject({
      code: "ERR_AUTHZ_PLACE_OUTSIDE",
    });
    expect(refused(() => resolveRole(catalog, "support", { at: "/org=a/" }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
  });
});

describe("stored roles", () => {
  const team = role("team", ["viewer", "chat:send"], "/org=acme");

  it("are visible at their home and under it, and nowhere else", () => {
    expect(resolveRole(catalog, "team", { at: "/org=acme", roles: [team] })).toEqual([
      "chat:send",
      "report:read",
    ]);
    expect(resolveRole(catalog, "team", { at: "/org=acme/unit=u", roles: [team] })).toHaveLength(2);
    expect(refused(() => resolveRole(catalog, "team", { roles: [team] }))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
    });
    expect(
      refused(() => resolveRole(catalog, "team", { at: "/org=acme-x", roles: [team] })),
    ).toMatchObject({ code: "ERR_AUTHZ_ROLE_INVALID" });
  });

  it("read the root for an absent home or `/`", () => {
    const wide = [role("wide", ["chat:read"]), role("slash", ["chat:read"], "/")];
    expect(resolveRole(catalog, "wide", { at: "/org=a", roles: wide })).toEqual(["chat:read"]);
    expect(resolveRole(catalog, "slash", { at: "/org=a", roles: wide })).toEqual(["chat:read"]);
  });

  it("read as the preset when a preset has the same name", () => {
    const shadow = role("viewer", ["*"]);
    expect(resolveRole(catalog, "viewer", { roles: [shadow] })).toEqual(["report:read"]);
    expect(roleReader(compiled, [shadow]).stored("viewer", "/")).toBeUndefined();
  });

  it("reference presets and stored roles at the same or a wider home", () => {
    const roles = [
      role("base", ["chat:read"]),
      role("mid", ["base", "chat:send"], "/org=acme"),
      role("top", ["mid", "-chat:read", "support"], "/org=acme/unit=u"),
    ];
    expect(resolveRole(catalog, "top", { at: "/org=acme/unit=u", roles })).toEqual([
      "chat:send",
      "report:read",
    ]);
  });

  it("give nothing when they reference a narrower home", () => {
    const roles = [
      role("narrow", ["chat:read"], "/org=acme"),
      role("wide", ["narrow", "chat:send"]),
    ];
    expect(resolveRole(catalog, "wide", { at: "/org=acme", roles })).toEqual([]);
  });

  it("fail closed for a role that no longer exists, and for every role naming it", () => {
    const roles = [
      role("broken", ["chat:read", "deleted"]),
      role("excluding", ["chat:read", "-deleted"]),
      role("above", ["broken", "chat:send"]),
    ];
    for (const name of ["broken", "excluding", "above"]) {
      expect(resolveRole(catalog, name, { roles })).toEqual([]);
    }
    const reader = roleReader(compiled, roles);
    expect(reader.resolve("deleted", "/")).toBe(NO_ROLE);
    expect(reader.exists("deleted", "/")).toBe(false);
    expect(reader.resolveStored(roles[2]!)).toMatchObject({
      reason: "reference",
      role: "broken",
      reference: "deleted",
    });
  });

  it("keep the rest of a role when an entry names an unknown permission", () => {
    const roles = [role("stale", ["chat:read", "gone:read", "-gone:write", "gone:*", "*:gone"])];
    expect(resolveRole(catalog, "stale", { roles })).toEqual(["chat:read"]);
  });

  it("give nothing for a cycle met when read, without throwing", () => {
    const roles = [
      role("a", ["b", "chat:read"]),
      role("b", ["-a"]),
      role("c", ["a"]),
      role("self", ["self"]),
    ];
    for (const name of ["a", "b", "c", "self"])
      expect(resolveRole(catalog, name, { roles })).toEqual([]);
  });

  it("are inert at a home that no longer fits the structure", () => {
    const roles = [role("lost", ["chat:read"], "/unit=u"), role("user", ["lost"])];
    expect(refused(() => resolveRole(catalog, "lost", { at: "/", roles }))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
    });
    expect(resolveRole(catalog, "user", { roles })).toEqual([]);
  });

  it("give nothing when two of one name are visible at one place, unless they are the same", () => {
    const clash = [role("dup", ["chat:read"]), role("dup", ["chat:send"], "/org=a")];
    expect(resolveRole(catalog, "dup", { at: "/org=a", roles: clash })).toEqual([]);
    expect(resolveRole(catalog, "dup", { at: "/", roles: clash })).toEqual(["chat:read"]);
    const same = [
      role("dup", ["chat:read", "chat:send"]),
      role("dup", ["chat:send", "chat:read"], "/"),
    ];
    expect(resolveRole(catalog, "dup", { roles: same })).toEqual(["chat:read", "chat:send"]);
  });

  it("answer the same when handed more roles than the call needs", () => {
    const needed = [role("team", ["viewer"], "/org=a")];
    const more = [
      ...needed,
      role("team", ["*"], "/org=b"),
      role("other", ["missing"]),
      role("loop", ["loop"]),
      role("odd", ["chat:read"], "/org=%41"),
    ];
    expect(resolveRole(catalog, "team", { at: "/org=a/unit=u", roles: more })).toEqual(
      resolveRole(catalog, "team", { at: "/org=a/unit=u", roles: needed }),
    );
  });

  it("refuse roles that are not stored roles in shape, and a malformed role that is read", () => {
    expect(refused(() => resolveRole(catalog, "x", { roles: "x" as never }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(
      refused(() => resolveRole(catalog, "x", { roles: [{ name: "x" }] as never })),
    ).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what: "roles" } });
    expect(
      refused(() => resolveRole(catalog, "x", { roles: [role("x", ["chat:read"], "/org=a/")] })),
    ).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what: "place" } });
    expect(refused(() => resolveRole(catalog, "x", { roles: [role("x", ["*:*"])] }))).toMatchObject(
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "entry" } },
    );
  });

  it("are found with their row for issuing", () => {
    const row = role("team", ["viewer"], "/org=a");
    const reader = roleReader(compiled, [row]);
    expect(reader.stored("team", "/org=a/unit=u")).toBe(row);
    expect(reader.stored("team", "/")).toBeUndefined();
    expect(reader.stored("viewer", "/")).toBeUndefined();
    expect(reader.exists("viewer", "/org=a")).toBe(true);
  });
});

describe("checkRoleDefinition", () => {
  const define = (definition: unknown, roles?: StoredRole[]) =>
    checkRoleDefinition(compiled, definition, { roles });

  it("returns what the role gives once written", () => {
    const result = define(role("helper", ["viewer", "chat:*", "-chat:kick"], "/org=a"));
    expect([...result.gives].toSorted()).toEqual(["chat:read", "chat:send", "report:read"]);
  });

  it("refuses a role that is not in shape, a name that is not a token, or a home that is not a place", () => {
    expect(refused(() => define(null))).toMatchObject({ code: "ERR_AUTHZ_MALFORMED" });
    expect(refused(() => define({ name: "x" }))).toMatchObject({ code: "ERR_AUTHZ_MALFORMED" });
    expect(refused(() => define(role("Team", ["chat:read"])))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(refused(() => define(role("team", ["chat:read"], "/org=a/")))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(refused(() => define(role("team", ["chat:read"], "/unit=u")))).toMatchObject({
      code: "ERR_AUTHZ_PLACE_OUTSIDE",
      cause: { place: "/unit=u" },
    });
    expect(refused(() => define(role("team", ["*:*"])))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
      cause: { what: "entry" },
    });
  });

  it("refuses an unknown permission", () => {
    for (const entry of ["gone:read", "-gone:read", "gone:*"]) {
      expect(refused(() => define(role("team", [entry])))).toMatchObject({
        code: "ERR_AUTHZ_PERMISSION_UNKNOWN",
      });
    }
  });

  it("refuses the name of a preset, or of a stored role along the same chain", () => {
    expect(refused(() => define(role("viewer", ["chat:read"])))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "viewer", reason: "preset" },
    });
    const existing = [role("team", ["chat:read"], "/org=a")];
    for (const home of ["/", "/org=a/unit=u"]) {
      expect(refused(() => define(role("team", ["chat:read"], home), existing))).toMatchObject({
        code: "ERR_AUTHZ_ROLE_INVALID",
        cause: { reason: "taken" },
      });
    }
    expect(define(role("team", ["chat:send"], "/org=b"), existing).gives.has("chat:send")).toBe(
      true,
    );
  });

  it("edits the role of the same name and home in place", () => {
    const roles = [role("a", ["b"], "/org=a"), role("b", ["chat:read"], "/org=a")];
    expect(refused(() => define(role("b", ["a"], "/org=a"), roles))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { reason: "cycle" },
    });
    expect([...define(role("b", ["chat:send"], "/org=a"), roles).gives]).toEqual(["chat:send"]);
  });

  it("refuses an unknown reference, a narrower one, a broken one and a cycle", () => {
    expect(refused(() => define(role("team", ["ghost"])))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "team", reason: "reference", reference: "ghost" },
    });
    expect(refused(() => define(role("team", ["-ghost"])))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { reason: "reference" },
    });
    const narrow = [role("inner", ["chat:read"], "/org=a")];
    expect(refused(() => define(role("team", ["inner"]), narrow))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { reason: "reference", reference: "inner" },
    });
    expect(define(role("team", ["inner"], "/org=a/unit=u"), narrow).gives.has("chat:read")).toBe(
      true,
    );
    const broken = [role("stale", ["deleted"])];
    expect(refused(() => define(role("team", ["stale"]), broken))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { reason: "reference", reference: "deleted" },
    });
    expect(refused(() => define(role("team", ["team"])))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { reason: "cycle" },
    });
    expect(refused(() => define(role("team", ["-team"])))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { reason: "cycle" },
    });
  });
});
