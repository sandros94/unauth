import { describe, expect, it } from "vitest";
import { compiledOf } from "../../src/z/_internal/compile.ts";
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
});
const compiled = compiledOf(catalog);

const role = (name: string, entries: string[]): StoredRole => ({ name, entries });

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

  it("refuse a name that is neither a preset nor a stored role handed in", () => {
    expect(refused(() => resolveRole(catalog, "ghost"))).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      status: 400,
      cause: { role: "ghost", reason: "unknown" },
    });
    expect(
      refused(() => resolveRole(catalog, "ghost", { roles: [role("team", ["viewer"])] })),
    ).toMatchObject({
      code: "ERR_AUTHZ_ROLE_INVALID",
      cause: { role: "ghost", reason: "unknown" },
    });
  });
});

describe("stored roles", () => {
  it("give what their entries resolve to, wherever they are assigned", () => {
    const team = role("team", ["viewer", "chat:send"]);
    expect(resolveRole(catalog, "team", { roles: [team] })).toEqual(["chat:send", "report:read"]);
  });

  it("read as the preset when a preset has the same name, alone or referenced", () => {
    const roles = [role("viewer", ["*"]), role("desk", ["viewer", "chat:read"])];
    expect(resolveRole(catalog, "viewer", { roles })).toEqual(["report:read"]);
    expect(resolveRole(catalog, "desk", { roles })).toEqual(["chat:read", "report:read"]);
    expect(roleReader(compiled, roles).resolve("viewer")).toBe(compiled.presets.get("viewer"));
  });

  it("reference presets and other stored roles", () => {
    const roles = [
      role("base", ["chat:read"]),
      role("mid", ["base", "chat:send"]),
      role("top", ["mid", "-chat:read", "support"]),
    ];
    expect(resolveRole(catalog, "top", { roles })).toEqual(["chat:send", "report:read"]);
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
    expect(reader.resolve("deleted")).toBe(NO_ROLE);
    expect(reader.exists("deleted")).toBe(false);
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

  it("give nothing for a cycle met when read, nor for a role referencing one, without throwing", () => {
    const roles = [
      role("a", ["b", "chat:read"]),
      role("b", ["-a"]),
      role("c", ["a", "chat:send"]),
      role("d", ["chat:send", "-c"]),
      role("self", ["self"]),
      role("fine", ["chat:send"]),
    ];
    for (const name of ["a", "b", "c", "d", "self"]) {
      expect(resolveRole(catalog, name, { roles })).toEqual([]);
      expect(resolveRole(catalog, name, { roles: roles.toReversed() })).toEqual([]);
    }
    expect(resolveRole(catalog, "fine", { roles })).toEqual(["chat:send"]);
  });

  it("refuse two roles of one name, even alike", () => {
    for (const roles of [
      [role("dup", ["chat:read"]), role("dup", ["chat:send"])],
      [role("dup", ["chat:read"]), role("dup", ["chat:read"])],
      [role("viewer", ["chat:read"]), role("viewer", ["chat:read"])],
    ]) {
      expect(refused(() => resolveRole(catalog, "support", { roles }))).toMatchObject({
        code: "ERR_AUTHZ_ROLE_INVALID",
        status: 400,
        cause: { role: roles[0]!.name, reason: "duplicate" },
      });
    }
  });

  it("answer the same when handed more roles than the call needs", () => {
    const needed = [role("team", ["viewer"])];
    const more = [...needed, role("other", ["missing"]), role("loop", ["loop"])];
    expect(resolveRole(catalog, "team", { roles: more })).toEqual(
      resolveRole(catalog, "team", { roles: needed }),
    );
  });

  it("refuse roles that are not stored roles in shape, and a malformed role that is read", () => {
    expect(refused(() => resolveRole(catalog, "x", { roles: "x" as never }))).toMatchObject({
      code: "ERR_AUTHZ_MALFORMED",
    });
    expect(
      refused(() => resolveRole(catalog, "x", { roles: [{ name: "x" }] as never })),
    ).toMatchObject({ code: "ERR_AUTHZ_MALFORMED", cause: { what: "roles" } });
    expect(refused(() => resolveRole(catalog, "x", { roles: [role("x", ["*:*"])] }))).toMatchObject(
      { code: "ERR_AUTHZ_MALFORMED", cause: { what: "entry" } },
    );
  });
});
