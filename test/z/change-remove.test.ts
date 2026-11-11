import { describe, expect, it } from "vitest";
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
  deny,
  exclude,
  place,
  remove,
} from "./_change-world.ts";

/**
 * A forge: Otto owns `acme`, Mia moderates it, Pete maintains project `p1`, Bob develops there.
 */
function forge(): World {
  return World.founded()
    .apply("root", place(allow("otto", "*", ACME)))
    .apply("otto", place(assign("mia", "moderator", ACME)))
    .apply("otto", place(assign("pete", "maintainer", P1)))
    .apply("pete", place(assign("bob", "developer", P1)));
}

describe("remove only what you could give", () => {
  it("lets a manager remove what it could have placed", () => {
    const world = forge();
    expect(world.accepts("pete", remove(assign("bob", "developer", P1)))).toBe(true);
    expect(world.accepts("otto", remove(assign("pete", "maintainer", P1)))).toBe(true);
    expect(world.accepts("otto", remove(assign("mia", "moderator", ACME)))).toBe(true);
  });

  it("never lets a lower manager strip a higher one", () => {
    const world = forge();
    expect(world.reasons("mia", remove(allow("otto", "*", ACME)))).toEqual(["not-held"]);
    expect(world.reasons("pete", remove(assign("mia", "moderator", ACME)))).toEqual([
      "not-manager",
      "not-held",
    ]);
    expect(world.reasons("pete", remove(allow("otto", "*", ACME)))).toEqual([
      "not-manager",
      "not-held",
    ]);
  });

  it("asks a deny or an exclusion to be removed by whoever holds what it names there", () => {
    const world = forge()
      .apply("otto", place(deny("bob", "repo:push", P1)))
      .apply("otto", place(exclude("bob", "report:read", P1)))
      .apply("otto", place(deny("bob", "billing:read", P1)));
    expect(world.accepts("pete", remove(deny("bob", "repo:push", P1)))).toBe(true);
    expect(world.accepts("pete", remove(exclude("bob", "report:read", P1)))).toBe(true);
    expect(world.reasons("pete", remove(deny("bob", "billing:read", P1)))).toEqual(["not-held"]);
    expect(world.reasons("mia", remove(deny("bob", "repo:push", P1)))).toEqual(["not-held"]);
  });

  it("asks the holding at the time of the change only, and nothing of denies under the place", () => {
    const world = World.founded()
      .apply("root", place(allow("cal", "access:manage", ACME, NOW + 30 * DAY)))
      .apply("root", place(allow("cal", "report:read", ACME, NOW + 10 * DAY)))
      .apply("root", place(deny("cal", "report:read", ARCHIVES)))
      .apply("root", place(allow("dana", "report:read", ACME)));
    expect(world.accepts("cal", remove(allow("dana", "report:read", ACME)))).toBe(true);
    world.time = NOW + 10 * DAY;
    expect(world.reasons("cal", remove(allow("dana", "report:read", ACME)))).toEqual(["not-held"]);
  });

  it("checks a statement that does not exist like any other", () => {
    const world = forge();
    expect(world.accepts("pete", remove(allow("nobody", "repo:push", P1)))).toBe(true);
    expect(world.reasons("pete", remove(allow("nobody", "repo:push", GLOBEX)))).toEqual([
      "not-manager",
      "not-held",
    ]);
  });

  it("lets the assigner of a preset remove its assignment", () => {
    const world = World.founded()
      .apply("root", place(allow("uma", "access:manage", ACME)))
      .apply("root", place(allow("uma", "member:assign", ACME)))
      .apply("uma", place(assign("bob", "accountant", P1)))
      .apply("root", place(assign("bob", "viewer", P1)));
    expect(world.accepts("uma", remove(assign("bob", "accountant", P1)))).toBe(true);
    expect(world.reasons("uma", remove(assign("bob", "viewer", P1)))).toEqual(["not-held"]);
  });

  it("asks a permanent manager to remove a permanent management", () => {
    const world = World.founded()
      .apply("root", place(allow("deploy", "*")))
      .apply("root", place(allow("tess", "*", "/", NOW + 30 * DAY)));
    expect(world.reasons("tess", remove(allow("deploy", "*")))).toEqual(["not-held"]);
    expect(world.accepts("tess", remove(allow("dana", "report:read", ACME)))).toBe(true);
    expect(world.accepts("root", remove(allow("deploy", "*")))).toBe(true);
    expect(world.accepts("deploy", remove(allow("tess", "*")))).toBe(true);
  });
});

describe("never lift your own restriction", () => {
  /** Lea develops at `p1`, has a deny and an exclusion on her, and manages nothing. */
  function lea(): World {
    return forge()
      .apply("pete", place(assign("lea", "developer", P1)))
      .apply("pete", place(allow("lea", "report:list", P1)))
      .apply("pete", place(deny("lea", "repo:push", P1)))
      .apply("pete", place(exclude("lea", "report:read", P1)));
  }

  it("lets the author leave an allow or a role, without managing or holding anything", () => {
    const world = lea();
    expect(world.accepts("lea", remove(assign("lea", "developer", P1)))).toBe(true);
    expect(world.accepts("lea", remove(allow("lea", "report:list", P1)))).toBe(true);
    expect(world.accepts("lea", remove(allow("lea", "billing:read", GLOBEX)))).toBe(true);
  });

  it("refuses removing a deny or an exclusion about the author", () => {
    const world = lea();
    expect(world.reasons("lea", remove(deny("lea", "repo:push", P1)))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
    expect(world.reasons("lea", remove(exclude("lea", "report:read", P1)))).toEqual([
      "not-manager",
      "not-held",
      "about-self",
    ]);
    expect(world.reasons("pete", remove(deny("pete", "repo:push", P1)))).toEqual(["about-self"]);
  });

  it("refuses it to a permanent manager too, whom it does not reach", () => {
    const world = World.founded().apply("root", place(allow("deploy", "*")));
    world.statements.push(deny("root", "report:read", ACME));
    expect(world.reasons("root", remove(deny("root", "report:read", ACME)))).toEqual([
      "about-self",
    ]);
    expect(world.accepts("deploy", remove(deny("root", "report:read", ACME)))).toBe(true);
  });

  it("checks a restriction on the author's group like any other", () => {
    const world = forge().apply("otto", place(deny("p1-devs", "repo:push", P1)));
    const pete = { subject: "pete", groups: ["p1-devs"] };
    expect(world.reasons(pete, remove(deny("p1-devs", "repo:push", P1)))).toEqual(["not-held"]);
    expect(world.accepts("pete", remove(deny("p1-devs", "repo:push", P1)))).toBe(true);
  });
});
