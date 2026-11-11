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
} from "./_change-world.ts";

/** A platform owner, and Olga administering the organisation `acme` as its maintainer. */
function acme(): World {
  return World.founded("root").apply("root", place(assign("olga", "maintainer", ACME)));
}

describe("manage where you change", () => {
  it("lets a manager of a wider place change a narrower one, and nowhere else", () => {
    const world = acme();
    expect(world.accepts("olga", place(allow("bob", "report:read", P1)))).toBe(true);
    expect(world.accepts("olga", place(allow("bob", "report:read", ACME)))).toBe(true);
    expect(world.reasons("olga", place(allow("bob", "report:read", GLOBEX)))).toEqual([
      "not-manager",
      "not-held",
    ]);
    expect(world.reasons("olga", place(allow("bob", "report:read")))).toEqual([
      "not-manager",
      "not-held",
    ]);
  });

  it("lets a group make its members managers", () => {
    const world = World.founded().apply("root", place(assign("acme-admins", "maintainer", ACME)));
    const ann = { subject: "ann", groups: ["acme-admins"] };
    expect(world.accepts(ann, place(allow("bob", "repo:push", P1)))).toBe(true);
    expect(world.reasons("ann", place(allow("bob", "repo:push", P1)))).toEqual([
      "not-manager",
      "not-held",
    ]);
  });

  it("refuses a manager whose management ended, however long the rest is held", () => {
    const world = World.founded()
      .apply("root", place(allow("cal", "access:manage", ACME, NOW + DAY)))
      .apply("root", place(allow("cal", "report:read", ACME)));
    expect(world.accepts("cal", place(allow("dana", "report:read", P1, NOW + DAY / 2)))).toBe(true);
    world.time = NOW + DAY;
    expect(world.reasons("cal", place(allow("dana", "report:read", P1)))).toEqual(["not-manager"]);
  });
});

describe("hand out only what you hold", () => {
  it("counts what is held through an implication or a wildcard, and refuses the rest", () => {
    const world = acme();
    expect(world.accepts("olga", place(allow("bob", "report:list", P1)))).toBe(true);
    expect(world.accepts("olga", place(allow("bob", "report:*", P1)))).toBe(true);
    expect(world.accepts("olga", place(assign("bob", "developer", P1)))).toBe(true);
    expect(world.reasons("olga", place(allow("bob", "billing:read", P1)))).toEqual(["not-held"]);
    expect(world.reasons("olga", place(allow("bob", "*:read", P1)))).toEqual(["not-held"]);
    expect(world.reasons("olga", place(assign("bob", "owner", P1)))).toEqual(["not-held"]);
    expect(world.reasons("olga", place(assign("bob", "accountant", P1)))).toEqual(["not-held"]);
  });

  it("asks a deny or an exclusion to name only what the author holds", () => {
    const world = acme();
    expect(world.accepts("olga", place(deny("bob", "report:write", P1)))).toBe(true);
    expect(world.accepts("olga", place(exclude("bob", "report:*", ACME)))).toBe(true);
    expect(world.accepts("olga", place(deny("bob", "report:*", P1)))).toBe(true);
    expect(world.reasons("olga", place(deny("bob", "billing:read", P1)))).toEqual(["not-held"]);
    expect(world.reasons("olga", place(exclude("bob", "*", ACME)))).toEqual(["not-held"]);
  });

  it("refuses what the author is denied at the place or above it", () => {
    const world = acme().apply("root", place(deny("olga", "repo:push", ACME)));
    expect(world.reasons("olga", place(allow("bob", "repo:push", P1)))).toEqual(["not-held"]);
    expect(world.reasons("olga", place(deny("bob", "repo:push", P1)))).toEqual(["not-held"]);
  });

  it("lets only a permanent manager place a permanent management", () => {
    const world = World.founded()
      .apply("root", place(allow("tess", "*", "/", NOW + 30 * DAY)))
      .apply("root", place(assign("olga", "owner", ACME)));
    expect(world.reasons("tess", place(allow("bob", "*")))).toEqual(["not-held"]);
    expect(world.reasons("olga", place(allow("bob", "*")))).toEqual(["not-manager", "not-held"]);
    expect(world.accepts("tess", place(allow("bob", "*", "/", NOW + DAY)))).toBe(true);
    expect(world.accepts("root", place(allow("deploy", "*")))).toBe(true);
  });
});

describe("never outlive the author's holding", () => {
  /**
   * Cal, a contractor, manages `acme` for thirty days. He reads reports through an allow that ends
   * in ten days and through `viewer`, assigned until day twenty.
   */
  function contractor(): World {
    return World.founded()
      .apply("root", place(allow("cal", "access:manage", ACME, NOW + 30 * DAY)))
      .apply("root", place(allow("cal", "report:read", ACME, NOW + 10 * DAY)))
      .apply("root", place(assign("cal", "viewer", ACME, NOW + 20 * DAY)));
  }

  it("accepts an allow that ends by the last end of the holding, and refuses one after it", () => {
    const world = contractor();
    expect(world.accepts("cal", place(allow("dana", "report:read", P1, NOW + 15 * DAY)))).toBe(
      true,
    );
    expect(world.accepts("cal", place(allow("dana", "report:read", P1, NOW + 20 * DAY)))).toBe(
      true,
    );
    expect(
      world.reasons("cal", place(allow("dana", "report:read", P1, NOW + 20 * DAY + 1))),
    ).toEqual(["not-held"]);
    expect(world.reasons("cal", place(allow("dana", "report:read", P1)))).toEqual(["not-held"]);
    expect(world.reasons("cal", place(assign("dana", "viewer", ACME, NOW + 25 * DAY)))).toEqual([
      "not-held",
    ]);
  });

  it("follows the holding as its statements end", () => {
    const world = contractor();
    world.time = NOW + 12 * DAY;
    expect(world.accepts("cal", place(allow("dana", "report:read", P1, NOW + 20 * DAY)))).toBe(
      true,
    );
    world.time = NOW + 20 * DAY;
    expect(world.reasons("cal", place(allow("dana", "report:read", P1, NOW + 21 * DAY)))).toEqual([
      "not-held",
    ]);
  });

  it("asks again once a deny on the author ends", () => {
    const world = World.founded()
      .apply("root", place(allow("cal", "access:manage", ACME)))
      .apply("root", place(allow("cal", "report:read", ACME, NOW + 10 * DAY)))
      .apply("root", place(deny("cal", "report:read", ACME, NOW + 2 * DAY)));
    expect(world.reasons("cal", place(allow("dana", "report:read", P1, NOW + 5 * DAY)))).toEqual([
      "not-held",
    ]);
    world.time = NOW + 2 * DAY;
    expect(world.accepts("cal", place(allow("dana", "report:read", P1, NOW + 5 * DAY)))).toBe(true);
  });

  it("lets a deny or an exclusion outlive the holding, since it gives nothing", () => {
    const world = contractor();
    expect(world.accepts("cal", place(deny("spammer", "report:read", ACME)))).toBe(true);
    expect(world.accepts("cal", place(exclude("spammer", "report:read", ACME)))).toBe(true);
    expect(world.accepts("cal", place(deny("spammer", "report:read", ACME, NOW + 90 * DAY)))).toBe(
      true,
    );
  });

  it("asks the same of a statement placed again with a later end", () => {
    const world = contractor().apply("cal", place(allow("dana", "report:read", P1, NOW + 5 * DAY)));
    expect(world.reasons("cal", place(allow("dana", "report:read", P1)))).toEqual(["not-held"]);
    expect(world.accepts("cal", place(allow("dana", "report:read", P1, NOW + 18 * DAY)))).toBe(
      true,
    );
    expect(world.accepts("root", place(allow("dana", "report:read", P1)))).toBe(true);
  });
});

describe("nothing the author is denied under the place", () => {
  /** Dan holds everything at `acme` and is denied reading in its archives. */
  function banned(): World {
    return World.founded()
      .apply("root", place(allow("dan", "*", ACME)))
      .apply("root", place(deny("dan", "report:read", ARCHIVES)));
  }

  it("refuses an allow or an assignment that would reach the ban", () => {
    const world = banned();
    expect(world.reasons("dan", place(allow("ike", "report:read", ACME)))).toEqual(["not-held"]);
    expect(world.reasons("dan", place(allow("ike", "report:write", ACME)))).toEqual(["not-held"]);
    expect(world.reasons("dan", place(assign("ike", "viewer", ACME)))).toEqual(["not-held"]);
    expect(world.reasons("dan", place(allow("ike", "*", ACME)))).toEqual(["not-held"]);
  });

  it("accepts what the ban does not block, and what stays beside the ban", () => {
    const world = banned();
    expect(world.accepts("dan", place(allow("ike", "report:list", ACME)))).toBe(true);
    expect(world.accepts("dan", place(allow("ike", "repo:push", ACME)))).toBe(true);
    expect(world.accepts("dan", place(allow("ike", "report:read", P1)))).toBe(true);
  });

  it("does not refuse a deny or an exclusion", () => {
    const world = banned();
    expect(world.accepts("dan", place(deny("ike", "report:read", ACME)))).toBe(true);
    expect(world.accepts("dan", place(exclude("ike", "report:read", ACME)))).toBe(true);
  });

  it("counts a ban on one of the author's groups, and not one that has ended", () => {
    const world = World.founded()
      .apply("root", place(allow("dan", "*", ACME)))
      .apply("root", place(deny("acme-staff", "report:read", ARCHIVES, NOW + DAY)));
    const dan = { subject: "dan", groups: ["acme-staff"] };
    expect(world.reasons(dan, place(allow("ike", "report:read", ACME)))).toEqual(["not-held"]);
    expect(world.accepts("dan", place(allow("ike", "report:read", ACME)))).toBe(true);
    world.time = NOW + DAY;
    expect(world.accepts(dan, place(allow("ike", "report:read", ACME)))).toBe(true);
  });

  it("does not refuse for an exclusion under the place", () => {
    const world = World.founded()
      .apply("root", place(allow("dan", "*", ACME)))
      .apply("root", place(exclude("dan", "report:read", ARCHIVES)));
    expect(world.accepts("dan", place(allow("ike", "report:read", ACME)))).toBe(true);
  });

  it("does not reach a permanent manager", () => {
    const world = World.founded().apply("olga", place(deny("root", "report:read", ARCHIVES)), {
      extra: [assign("olga", "owner", ACME)],
    });
    expect(world.accepts("root", place(allow("ike", "report:read", ACME)))).toBe(true);
  });
});

describe("never for yourself", () => {
  it("refuses a statement about the author's own identifier, never one about its group", () => {
    const world = acme();
    const olga = { subject: "olga", groups: ["acme-admins"] };
    expect(world.reasons(olga, place(assign("olga", "developer", P1)))).toEqual(["about-self"]);
    expect(world.reasons(olga, place(deny("olga", "repo:push", P1)))).toEqual(["about-self"]);
    expect(world.reasons(olga, place(exclude("olga", "repo:push", P1)))).toEqual(["about-self"]);
    expect(world.accepts(olga, place(assign("acme-admins", "developer", P1)))).toBe(true);
    expect(world.accepts(olga, place(deny("acme-admins", "repo:push", P1)))).toBe(true);
  });

  it("holds for a permanent manager too", () => {
    const world = World.founded();
    expect(world.reasons("root", place(deny("root", "report:read", ACME)))).toEqual(["about-self"]);
    expect(world.reasons("root", place(allow("root", "report:read", ACME)))).toEqual([
      "about-self",
    ]);
  });
});

describe("a preset assigned by its assigner", () => {
  /** Uma manages the people of `acme`: she assigns `accountant` and reads no bill herself. */
  function people(end?: number): World {
    return World.founded()
      .apply("root", place(allow("uma", "access:manage", ACME)))
      .apply("root", place(allow("uma", "member:assign", ACME, end)));
  }

  it("is assigned without holding what it gives", () => {
    const world = people();
    expect(world.accepts("uma", place(assign("bob", "accountant", P1)))).toBe(true);
    expect(world.accepts("uma", place(assign("bob", "accountant", ACME)))).toBe(true);
  });

  it("replaces only the holding: the place, the subject and the other presets still count", () => {
    const world = people();
    expect(world.reasons("uma", place(assign("bob", "accountant", GLOBEX)))).toEqual([
      "not-manager",
      "not-held",
    ]);
    expect(world.reasons("uma", place(assign("uma", "accountant", ACME)))).toEqual(["about-self"]);
    expect(world.reasons("uma", place(assign("bob", "viewer", ACME)))).toEqual(["not-held"]);
    expect(world.reasons("uma", place(allow("bob", "billing:read", ACME)))).toEqual(["not-held"]);
    world.time = NOW + 2 * DAY;
    expect(world.reasons("uma", place(assign("bob", "accountant", ACME, NOW + DAY)))).toEqual([
      "ended",
    ]);
  });

  it("is not assigned for longer than the assigner permission is held", () => {
    const world = people(NOW + 10 * DAY);
    expect(world.accepts("uma", place(assign("bob", "accountant", ACME, NOW + 10 * DAY)))).toBe(
      true,
    );
    expect(world.reasons("uma", place(assign("bob", "accountant", ACME, NOW + 11 * DAY)))).toEqual([
      "not-held",
    ]);
    expect(world.reasons("uma", place(assign("bob", "accountant", ACME)))).toEqual(["not-held"]);
  });

  it("falls back to holding what it gives", () => {
    const world = people(NOW + 10 * DAY).apply("root", place(allow("uma", "billing:read", ACME)));
    expect(world.reasons("uma", place(assign("bob", "accountant", ACME)))).toEqual(["not-held"]);
    world.apply("root", place(allow("uma", "report:read", ACME)));
    expect(world.accepts("uma", place(assign("bob", "accountant", ACME)))).toBe(true);
  });

  it("is not refused for a deny under the place of what the preset gives", () => {
    const world = people().apply("root", place(deny("uma", "billing:read", ARCHIVES)));
    expect(world.accepts("uma", place(assign("bob", "accountant", ACME)))).toBe(true);
  });

  it("is refused when the assigner permission itself is denied at the place", () => {
    const world = people().apply("root", place(deny("uma", "member:assign", ACME)));
    expect(world.reasons("uma", place(assign("bob", "accountant", ACME)))).toEqual(["not-held"]);
  });
});
