import { describe, expect, it } from "vitest";
import { defineCatalog } from "../../src/z/catalog.ts";
import { decide } from "../../src/z/decide.ts";
import {
  ACME,
  ARCHIVES,
  DAY,
  NOW,
  P1,
  World,
  allow,
  assign,
  deny,
  exclude,
  place,
  remove,
} from "./_change-world.ts";

function may(
  world: World,
  who: { subject: string; groups?: string[] },
  permission: string,
  at?: string,
): boolean {
  return decide(
    world.catalog,
    { ...who, permission, ...(at && { place: at }) },
    { statements: world.statements, roles: world.roles, now: () => world.time * 1000 },
  ).allowed;
}

describe("one person and an assistant, no places", () => {
  const blog = defineCatalog({
    permissions: ["post:read", "post:draft", "post:publish", "access:manage"],
    places: false,
    manager: "access:manage",
  });

  it("Ed founds the tree, gives his assistant drafting, and later publishing", () => {
    const world = new World(blog).genesis(allow("ed", "*"));
    world
      .apply("ed", place(allow("assistant", "post:read")))
      .apply("ed", place(allow("assistant", "post:draft")));
    const assistant = { subject: "assistant" };
    expect(may(world, assistant, "post:read")).toBe(true);
    expect(may(world, assistant, "post:draft")).toBe(true);
    expect(may(world, assistant, "post:publish")).toBe(false);
    expect(may(world, { subject: "ed" }, "post:publish")).toBe(true);
    expect(world.reasons("assistant", place(allow("assistant", "post:publish")))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
    world.apply("ed", place(allow("assistant", "post:publish")));
    expect(may(world, assistant, "post:publish")).toBe(true);
  });
});

describe("a code forge", () => {
  /** The web team writes in one project, Lea develops there, Mel manages its access. */
  function forgeWorld(): World {
    return World.founded("owner")
      .apply("owner", place(assign("web-team", "developer", P1)))
      .apply("owner", place(assign("lea", "developer", P1)))
      .apply("owner", place(allow("mel", "access:manage", P1)))
      .apply("owner", place(deny("lea", "repo:push", P1)));
  }

  it("Lea leaves her role, and neither lifts her deny nor gives herself a role", () => {
    const world = forgeWorld();
    expect(world.accepts("lea", remove(assign("lea", "developer", P1)))).toBe(true);
    expect(world.reasons("lea", remove(deny("lea", "repo:push", P1)))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
    expect(world.reasons("lea", place(assign("lea", "developer", P1)))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
  });

  it("Mel, removed as a manager, may change nothing a minute later", () => {
    const world = forgeWorld().apply("owner", remove(allow("mel", "access:manage", P1)));
    world.time = NOW + 60;
    expect(world.reasons("mel", place(assign("mel-alt", "maintainer", P1)))).toEqual([
      "not-manager",
      "not-held",
    ]);
  });

  it("Mia, a moderator, cannot strip the owner, and the owner strips the moderators", () => {
    const world = World.founded("owner")
      .apply("owner", place(allow("otto", "*", ACME)))
      .apply("otto", place(assign("mia", "moderator", ACME)))
      .apply("otto", place(assign("moderators", "moderator", ACME)));
    expect(world.reasons("mia", remove(allow("otto", "*", ACME)))).toEqual(["not-held"]);
    expect(world.accepts("otto", remove(assign("moderators", "moderator", ACME)))).toBe(true);
  });

  it("Cal, whose holding ends with the month, gives only until then, and denies for good", () => {
    const month = NOW + 30 * DAY;
    const world = World.founded("owner")
      .apply("owner", place(allow("cal", "access:manage", P1, month)))
      .apply("owner", place(assign("cal", "maintainer", P1, month)));
    expect(world.reasons("cal", place(assign("dana", "maintainer", P1)))).toEqual(["not-held"]);
    expect(world.accepts("cal", place(assign("dana", "maintainer", P1, month)))).toBe(true);
    expect(world.accepts("cal", place(deny("spammer", "repo:push", P1)))).toBe(true);
  });
});

describe("a cloud account tree", () => {
  /** The owner and the deploy job hold a permanent management. Tom administers `acme`. */
  function cloud(): World {
    return World.founded("owner")
      .apply("owner", place(allow("deploy", "*")))
      .apply("owner", place(allow("tom", "*", ACME)));
  }
  const tom = { subject: "tom", groups: ["acme-members"] };

  it("the owner denies the members a permission, Tom included", () => {
    const world = cloud().apply("owner", place(deny("acme-members", "audit-log:delete", ACME)));
    expect(may(world, tom, "audit-log:delete", ACME)).toBe(false);
    expect(
      may(world, { subject: "newcomer", groups: ["acme-members"] }, "audit-log:delete", P1),
    ).toBe(false);
    expect(may(world, { subject: "owner" }, "audit-log:delete", ACME)).toBe(true);
  });

  it("Tom denies his own group, cannot lift it, and the owner does", () => {
    const world = cloud().apply(tom, place(deny("acme-members", "report:write", ACME)));
    expect(may(world, tom, "report:write", ACME)).toBe(false);
    expect(world.reasons(tom, remove(deny("acme-members", "report:write", ACME)))).toEqual([
      "not-held",
    ]);
    expect(world.accepts("owner", remove(deny("acme-members", "report:write", ACME)))).toBe(true);
  });

  it("a deny on a permanent manager is accepted and does not apply while it holds one", () => {
    const world = cloud().apply(tom, place(deny("owner", "report:read", ACME)));
    expect(may(world, { subject: "owner" }, "report:read", ACME)).toBe(true);
    world.apply("owner", place(deny("staff", "access:manage", "/")));
    const job = { subject: "deploy", groups: ["staff"] };
    expect(may(world, job, "access:manage", ACME)).toBe(true);
    expect(world.accepts(job, remove(deny("staff", "access:manage")))).toBe(true);
  });

  it("Dan, denied reading the archives, cannot allow reading the organisation", () => {
    const denied = cloud()
      .apply("owner", place(allow("dan", "*", ACME)))
      .apply("owner", place(deny("dan", "report:read", ARCHIVES)));
    expect(denied.reasons("dan", place(allow("ike", "report:read", ACME)))).toEqual(["not-held"]);
    const excluded = cloud()
      .apply("owner", place(allow("dan", "*", ACME)))
      .apply("owner", place(exclude("dan", "report:read", ARCHIVES)));
    expect(excluded.accepts("dan", place(allow("ike", "report:read", ACME)))).toBe(true);
  });
});
