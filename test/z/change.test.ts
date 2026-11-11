import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import { type Change, checkChange } from "../../src/z/change.ts";
import type { Statement } from "../../src/z/types.ts";
import {
  ACME,
  ARCHIVES,
  DAY,
  GLOBEX,
  NOW,
  P1,
  World,
  allow,
  assign,
  define,
  deny,
  exclude,
  forge,
  place,
  remove,
} from "./_change-world.ts";
import { refused } from "./_expect.ts";

describe("an ordinary change never opens the root", () => {
  it("refuses a first permanent manager although the root holds none and says so", () => {
    const world = new World();
    expect(world.reasons("ed", place(allow("ed", "*")), { managers: [] })).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
    expect(world.reasons("ed", place(allow("deploy", "*")), { managers: [] })).toEqual([
      "not-manager",
      "not-held",
    ]);
    expect(
      world.reasons({ subject: "ed", groups: ["admins"] }, place(allow("admins", "*")), {
        managers: [],
      }),
    ).toEqual(["not-manager", "not-held"]);
    expect(world.reasons("ed", place(allow("ed", "*")), { managers: false })).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
  });

  it("refuses it to a manager of the root whose holding ends", () => {
    const world = new World();
    world.statements.push(allow("ops", "*", "/", NOW + DAY));
    expect(world.reasons("ops", place(allow("svc", "*")), { managers: [] })).toEqual(["not-held"]);
    expect(world.reasons("ops", place(allow("ops", "*")), { managers: [] })).toEqual([
      "not-held",
      "about-self",
    ]);
  });

  it("refuses anyone else once the root holds one", () => {
    const world = World.founded("ed");
    expect(world.reasons("mallory", place(allow("mallory", "*")))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
    expect(world.reasons("mallory", place(allow("eve", "*")))).toEqual(["not-manager", "not-held"]);
  });

  it("is refused, with every change, by a catalog that designates no manager", () => {
    const flat = defineCatalog({ permissions: ["post:read", "post:publish"] });
    const world = new World(flat);
    world.statements.push(allow("ed", "*"));
    expect(world.reasons("ed", place(allow("bot", "post:read")))).toEqual(["not-manager"]);
    expect(world.reasons("ed", remove(allow("bot", "post:read")))).toEqual(["not-manager"]);
  });
});

describe("the root keeps a permanent management", () => {
  it("refuses removing the last one, even by its own holder", () => {
    const world = World.founded("root");
    expect(world.reasons("root", remove(allow("root", "*")))).toEqual(["last-manager"]);
    world.apply("root", place(allow("deploy", "*")));
    expect(world.accepts("root", remove(allow("root", "*")))).toBe(true);
    expect(world.accepts("root", remove(allow("deploy", "*")))).toBe(true);
    world.apply("deploy", remove(allow("root", "*")));
    expect(world.reasons("deploy", remove(allow("deploy", "*")))).toEqual(["last-manager"]);
  });

  it("refuses ending the last one, and allows ending one of two", () => {
    const world = World.founded("root");
    expect(world.reasons("root", place(allow("root", "*", "/", NOW + DAY)))).toEqual([
      "about-self",
      "last-manager",
    ]);
    world.apply("root", place(allow("deploy", "*")));
    expect(world.accepts("root", place(allow("deploy", "*", "/", NOW + DAY)))).toBe(true);
  });

  it("refuses removing the last one when it is about a group the author is in", () => {
    const world = new World().genesis(allow("admins", "*"));
    const alice = { subject: "alice", groups: ["admins"] };
    expect(world.reasons(alice, remove(allow("admins", "*")))).toEqual(["last-manager"]);
    world.apply(alice, place(allow("deploy", "*")));
    expect(world.accepts(alice, remove(allow("admins", "*")))).toBe(true);
  });

  it("refuses any change to such a statement without the permanent managements handed in", () => {
    const world = World.founded("root").apply("root", place(allow("deploy", "*")));
    expect(world.reasons("root", remove(allow("deploy", "*")), { managers: false })).toEqual([
      "last-manager",
    ]);
    expect(
      world.reasons("root", place(allow("deploy", "*", "/", NOW + DAY)), { managers: false }),
    ).toEqual(["last-manager"]);
    expect(world.accepts("root", place(allow("ops", "*")), { managers: false })).toBe(true);
    expect(world.accepts("root", place(allow("ops", "report:read")), { managers: false })).toBe(
      true,
    );
  });

  it("counts what is handed in as managers, and only its permanent managements", () => {
    const world = World.founded("root").apply("root", place(allow("deploy", "*")));
    const managers = [
      allow("root", "*"),
      allow("deploy", "*", "/", NOW + DAY),
      allow("x", "*", ACME),
    ];
    expect(world.accepts("root", remove(allow("deploy", "*")), { managers })).toBe(true);
    expect(
      world.reasons("root", remove(allow("root", "*")), { managers: [allow("root", "*")] }),
    ).toEqual(["last-manager"]);
  });
});

describe("refusals", () => {
  it("name every reason at once, in a fixed order", () => {
    const world = World.founded();
    world.time = NOW + DAY;
    expect(world.reasons("bob", place(allow("bob", "report:read", ACME, NOW)))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
      "ended",
    ]);
    expect(world.reasons("bob", place(deny("bob", "report:read", ACME, NOW + DAY)))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
      "ended",
    ]);
  });

  it("refuse a statement already ended, and accept one that ends a second later", () => {
    const world = World.founded();
    expect(world.reasons("root", place(deny("bob", "report:read", ACME, NOW)))).toEqual(["ended"]);
    expect(world.reasons("root", place(allow("bob", "report:read", ACME, NOW - 1)))).toEqual([
      "ended",
    ]);
    expect(world.accepts("root", place(deny("bob", "report:read", ACME, NOW + 1)))).toBe(true);
  });

  it("carry the code, the status and the reasons as the error contract declares", () => {
    const world = World.founded();
    const error = world.error("bob", place(allow("eve", "report:read")));
    expect(error.code).toBe("ERR_AUTHZ_CHANGE_REFUSED");
    expect(error.status).toBe(403);
    expect(error.cause).toEqual({ reasons: ["not-manager", "not-held"] });
  });
});

describe("the input is refused before any rule", () => {
  const world = World.founded();
  const codeOf = (author: unknown, change: unknown, extra?: Record<string, unknown>) =>
    refused(() =>
      checkChange(forge, change as Change, {
        author: author as string,
        statements: world.statements,
        now: () => NOW * 1000,
        ...extra,
      }),
    );

  it("a malformed author, groups or action", () => {
    const statement = allow("bob", "report:read", ACME);
    const valid = place(statement);
    for (const author of ["", 7, undefined, null]) {
      expect(codeOf(author, valid).code).toBe("ERR_AUTHZ_MALFORMED");
    }
    for (const groups of ["team", [1], [null], {}]) {
      expect(codeOf("bob", valid, { groups }).code).toBe("ERR_AUTHZ_MALFORMED");
    }
    for (const change of [
      null,
      "place",
      { action: "edit", statement },
      { action: "place" },
      { statement },
    ]) {
      expect(codeOf("bob", change).code).toBe("ERR_AUTHZ_MALFORMED");
    }
  });

  it("a statement being placed that is not in its shape, its place or its catalog", () => {
    const cases: [Statement, string][] = [
      [{ ...allow("bob", "report:read"), kind: "grant" as "allow" }, "ERR_AUTHZ_MALFORMED"],
      [allow("bob", "report:read", "/org=acme/"), "ERR_AUTHZ_MALFORMED"],
      [allow("bob", "report:read", ACME, NOW * 1000), "ERR_AUTHZ_MALFORMED"],
      [allow("bob", "*:*", ACME), "ERR_AUTHZ_MALFORMED"],
      [allow("", "report:read", ACME), "ERR_AUTHZ_MALFORMED"],
      [allow("bob", "report:delete", ACME), "ERR_AUTHZ_PERMISSION_UNKNOWN"],
      [deny("bob", "invoice:*", ACME), "ERR_AUTHZ_PERMISSION_UNKNOWN"],
      [exclude("bob", "*:delete-all", ACME), "ERR_AUTHZ_PERMISSION_UNKNOWN"],
      [allow("bob", "report:read", "/team=x"), "ERR_AUTHZ_PLACE_OUTSIDE"],
      [deny("bob", "report:read", "/org=acme/archive=a"), "ERR_AUTHZ_PLACE_OUTSIDE"],
      [assign("bob", "Viewer", ACME), "ERR_AUTHZ_MALFORMED"],
      [assign("bob", "auditor", ACME), "ERR_AUTHZ_ROLE_INVALID"],
    ];
    for (const [statement, code] of cases) {
      expect([statement, codeOf("mallory", place(statement)).code]).toEqual([statement, code]);
    }
    expect(codeOf("mallory", place(assign("bob", "auditor", ACME))).cause).toEqual({
      role: "auditor",
      reason: "unknown",
    });
  });

  it("an assignment of a stored role outside its home", () => {
    const local = World.founded();
    local.apply("root", define({ name: "triage", home: P1, entries: ["report:read"] }));
    expect(local.accepts("root", place(assign("bob", "triage", P1)))).toBe(true);
    expect(local.error("root", place(assign("bob", "triage", ACME))).cause).toEqual({
      role: "triage",
      reason: "unknown",
    });
  });

  it("a statement being removed that is not in its shape or not at a canonical key", () => {
    expect(codeOf("mallory", remove(allow("bob", "report:read", "/org=acme/"))).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
    expect(codeOf("mallory", remove(allow("bob", "*:*"))).code).toBe("ERR_AUTHZ_MALFORMED");
    expect(codeOf("mallory", remove({ kind: "allow" } as Statement)).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
  });

  it("a role being defined against the rules on stored roles", () => {
    expect(codeOf("mallory", define({ name: "viewer", entries: ["report:read"] })).cause).toEqual({
      role: "viewer",
      reason: "preset",
    });
    expect(codeOf("mallory", define({ name: "x", entries: ["report:delete"] })).code).toBe(
      "ERR_AUTHZ_PERMISSION_UNKNOWN",
    );
    expect(codeOf("mallory", define({ name: "x", home: "/team=a", entries: [] })).code).toBe(
      "ERR_AUTHZ_PLACE_OUTSIDE",
    );
    expect(codeOf("mallory", define({ name: "x", entries: ["x"] })).cause).toMatchObject({
      reason: "cycle",
    });
  });

  it("permanent managements handed in that are not statements", () => {
    expect(codeOf("root", remove(allow("deploy", "*")), { managers: "root" }).code).toBe(
      "ERR_AUTHZ_MALFORMED",
    );
  });
});

describe("statements that are inert may be removed", () => {
  it("an unknown permission, a place that no longer fits, a role that no longer exists", () => {
    const world = World.founded().apply("root", place(assign("olga", "maintainer", ACME)));
    expect(world.accepts("olga", remove(allow("bob", "report:delete", ACME)))).toBe(true);
    expect(world.accepts("olga", remove(deny("bob", "invoice:*", ACME)))).toBe(true);
    expect(world.accepts("olga", remove(allow("bob", "billing:read", "/org=acme/team=t")))).toBe(
      true,
    );
    expect(world.accepts("olga", remove(assign("bob", "auditor", ACME)))).toBe(true);
    expect(world.reasons("olga", remove(allow("bob", "report:delete", GLOBEX)))).toEqual([
      "not-manager",
    ]);
    expect(world.reasons("olga", remove(deny("olga", "invoice:*", ACME)))).toEqual(["about-self"]);
  });
});

describe("handing in more statements never changes a result", () => {
  const unrelated: Statement[] = [
    allow("zed", "*", ACME),
    deny("zed", "report:read", ARCHIVES),
    deny("other-team", "*", ACME),
    exclude("other-team", "report:write", ACME),
    allow("cal", "report:read", GLOBEX, NOW + DAY),
    assign("dana", "maintainer", P1),
    deny("cal", "report:read", GLOBEX),
    allow("deploy-x", "*", ACME, NOW + 3 * DAY),
  ];

  it("for every change of a small organisation", () => {
    const world = World.founded()
      .apply("root", place(assign("olga", "maintainer", ACME)))
      .apply("root", place(allow("cal", "access:manage", ACME, NOW + 30 * DAY)))
      .apply("root", place(allow("cal", "report:read", ACME, NOW + 10 * DAY)))
      .apply("root", place(deny("dan", "report:read", ARCHIVES)))
      .apply("root", place(allow("dan", "*", ACME)));
    const changes: [string, Change][] = [
      ["olga", place(allow("bob", "report:read", P1))],
      ["olga", place(allow("bob", "billing:read", P1))],
      ["olga", place(assign("olga", "viewer", P1))],
      ["cal", place(allow("bob", "report:read", ACME, NOW + 5 * DAY))],
      ["cal", place(allow("bob", "report:read", ACME, NOW + 20 * DAY))],
      ["dan", place(allow("ike", "report:read", ACME))],
      ["dan", place(exclude("ike", "report:read", ACME))],
      ["olga", remove(allow("cal", "report:read", ACME))],
      ["olga", define({ name: "triage", home: ACME, entries: ["report:read", "repo:push"] })],
      ["olga", define({ name: "triage", home: ACME, entries: ["billing:read"] })],
      ["root", remove(allow("root", "*"))],
    ];
    const outcome = (extra: Statement[]) =>
      changes.map(([author, change]) =>
        world.accepts(author, change, { extra })
          ? "accepted"
          : world.reasons(author, change, { extra }),
      );
    const bare = outcome([]);
    expect(bare.filter((result) => result === "accepted")).toHaveLength(5);
    expect(outcome(unrelated)).toEqual(bare);
  });
});
