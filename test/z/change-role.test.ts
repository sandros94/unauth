import { describe, expect, it } from "vitest";
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
  define,
  deny,
  exclude,
  forge,
  place,
} from "./_change-world.ts";

/** Olga administers `acme` as its maintainer. */
function acme(): World {
  return World.founded().apply("root", place(assign("olga", "maintainer", ACME)));
}

describe("a stored role is defined at its home", () => {
  it("by a manager of the home who holds what it gives there", () => {
    const world = acme();
    const triage = { name: "triage", home: ACME, entries: ["report:read", "repo:push"] };
    expect(world.accepts("olga", define(triage))).toBe(true);
    expect(world.accepts("olga", define({ ...triage, home: P1 }))).toBe(true);
    expect(world.accepts("olga", define({ ...triage, entries: ["developer", "-repo:push"] }))).toBe(
      true,
    );
    world.apply("olga", define(triage)).apply("olga", place(assign("bob", "triage", P1)));
  });

  it("refused to a subject that does not manage the home", () => {
    const world = acme();
    expect(
      world.reasons("bob", define({ name: "x", home: ACME, entries: ["report:read"] })),
    ).toEqual(["not-manager", "not-held"]);
    expect(world.reasons("olga", define({ name: "x", entries: ["report:read"] }))).toEqual([
      "not-manager",
      "not-held",
    ]);
    world.apply("root", place(allow("olga", "report:read")));
    expect(world.reasons("olga", define({ name: "x", entries: ["report:read"] }))).toEqual([
      "not-manager",
    ]);
  });

  it("refused when it gives what the author does not hold there", () => {
    const world = acme();
    expect(
      world.reasons("olga", define({ name: "x", home: ACME, entries: ["billing:read"] })),
    ).toEqual(["not-held"]);
    expect(world.reasons("olga", define({ name: "x", home: ACME, entries: ["owner"] }))).toEqual([
      "not-held",
    ]);
    expect(world.reasons("olga", define({ name: "x", home: ACME, entries: ["*:read"] }))).toEqual([
      "not-held",
    ]);
  });

  it("refused to an author whose holding ends, however long it lasts", () => {
    const world = World.founded()
      .apply("root", place(allow("cal", "access:manage", ACME)))
      .apply("root", place(allow("cal", "report:read", ACME, NOW + 300 * DAY)));
    expect(
      world.reasons("cal", define({ name: "x", home: ACME, entries: ["report:read"] })),
    ).toEqual(["not-held"]);
    expect(world.accepts("cal", define({ name: "x", home: ACME, entries: ["report:list"] }))).toBe(
      false,
    );
    world.apply("root", place(allow("cal", "report:list", ACME)));
    expect(world.accepts("cal", define({ name: "x", home: ACME, entries: ["report:list"] }))).toBe(
      true,
    );
  });

  it("refused when the author is denied what it gives under the home, never for an exclusion", () => {
    const world = World.founded()
      .apply("root", place(allow("dan", "*", ACME)))
      .apply("root", place(deny("dan", "report:read", ARCHIVES)))
      .apply("root", place(exclude("dan", "repo:push", ARCHIVES)));
    expect(world.reasons("dan", define({ name: "x", home: ACME, entries: ["report:*"] }))).toEqual([
      "not-held",
    ]);
    expect(world.accepts("dan", define({ name: "x", home: ACME, entries: ["repo:push"] }))).toBe(
      true,
    );
    expect(world.accepts("dan", define({ name: "x", home: P1, entries: ["report:*"] }))).toBe(true);
  });

  it("defined anywhere by a permanent manager", () => {
    const world = World.founded();
    expect(world.accepts("root", define({ name: "all", entries: ["*"] }))).toBe(true);
    expect(world.accepts("root", define({ name: "all", home: P1, entries: ["owner"] }))).toBe(true);
  });
});

describe("a stored role is edited", () => {
  /** Olga defined `triage`, and holds a stored role `ops` the platform owner defined for her. */
  function edited(): World {
    return acme()
      .apply("olga", define({ name: "triage", home: ACME, entries: ["report:read"] }))
      .apply("root", define({ name: "ops", home: ACME, entries: ["access:manage", "report:read"] }))
      .apply("root", place(assign("ivy", "ops", ACME)));
  }

  it("within what the author holds at the home", () => {
    const world = edited();
    expect(
      world.accepts(
        "olga",
        define({ name: "triage", home: ACME, entries: ["report:*", "repo:push"] }),
      ),
    ).toBe(true);
  });

  it("refused beyond what the author holds, as defining it would be", () => {
    const world = edited();
    expect(
      world.reasons(
        "olga",
        define({ name: "triage", home: ACME, entries: ["report:read", "billing:read"] }),
      ),
    ).toEqual(["not-held"]);
  });

  it("asks what the author holds before the edit, never through the role being edited", () => {
    const world = edited();
    expect(
      world.reasons(
        "ivy",
        define({ name: "ops", home: ACME, entries: ["access:manage", "report:*"] }),
      ),
    ).toEqual(["not-held"]);
    expect(
      world.accepts(
        "ivy",
        define({ name: "ops", home: ACME, entries: ["access:manage", "report:list"] }),
      ),
    ).toBe(true);
    const before = decide(
      forge,
      { subject: "ivy", permission: "report:write", place: ACME },
      { statements: world.statements, roles: world.roles, now: () => NOW * 1000 },
    );
    expect(before.allowed).toBe(false);
  });
});
