import { describe, expect, it } from "vitest";
import { type Catalog, defineCatalog } from "../../../src/z/catalog.ts";
import { ask } from "../../../src/z/ask.ts";
import { could, issueGrants } from "../../../src/z/grants.ts";
import type { Decision, Statement, StoredRole } from "../../../src/z/types.ts";

const HOUR = 3600;
const DAY = 86400;
const MONDAY = 1794214800;
const THURSDAY = 1794441600;
const FRIDAY = 1794528000;
const SATURDAY = 1794614400;
const NEXT_MONDAY = 1794819600;
const LATER = [MONDAY, MONDAY + HOUR, MONDAY + 2 * HOUR, THURSDAY, FRIDAY - 1, FRIDAY, SATURDAY];
const WEEK_AFTER = [...LATER, NEXT_MONDAY - 1, NEXT_MONDAY, NEXT_MONDAY + DAY];

const catalog = defineCatalog({
  permissions: [
    "report:list",
    "report:read",
    "report:write",
    "event:read",
    "event:manage",
    "chat:read",
    "chat:send",
    "match:join",
    "file:read",
    "file:write",
    "limited-file:read",
    "audit-log:delete",
    "access:manage",
  ],
  implies: {
    "report:write": ["report:read"],
    "report:read": ["report:list"],
    "event:manage": ["event:read"],
    "file:write": ["file:read"],
  },
  presets: {
    analyst: ["report:write"],
    writer: ["report:write", "chat:send"],
    lead: ["report:*", "event:manage"],
    player: ["chat:*", "match:join"],
    viewer: ["file:read", "report:read"],
    support: ["*:read", "-report:read"],
    owner: ["*"],
  },
  places: {
    "/": ["org", "server", "drive"],
    "org": ["area", "unit", "project", "report"],
    "area": ["archive"],
    "server": ["channel"],
    "drive": ["folder"],
    "folder": ["folder", "file"],
  },
});

interface World {
  readonly catalog: Catalog;
  readonly statements: readonly Statement[];
  readonly roles?: readonly StoredRole[];
  readonly places: readonly string[];
  readonly times: readonly number[];
}

interface Asker {
  readonly subject: string;
  /** The groups the application knows the subject in: their statements are read with its own. */
  readonly groups?: readonly string[];
  readonly bases?: readonly string[];
  readonly issuedAt?: number;
}

/**
 * Reads the statements about `asker` and its groups, as the application does, issues grants from
 * them at its time of issue, then asks every permission at every place and every later time of the
 * world, of the statements and of the grants, and expects the same outcome and the same kind of
 * reason. A place outside every base must read as not covered. Returns every
 * disagreement, and whether both outcomes were met, so a world shows it exercised them.
 */
function agree(world: World, asker: Asker) {
  const issuedAt = asker.issuedAt ?? MONDAY;
  const { subject, groups = [] } = asker;
  const identifiers = new Set([subject, ...groups]);
  const read = {
    subject,
    statements: world.statements.filter((statement) => identifiers.has(statement.subject)),
    roles: world.roles,
  };
  const grants = issueGrants(world.catalog, read, {
    bases: asker.bases,
    now: () => issuedAt * 1000,
  });
  const bases = asker.bases ?? ["/"];
  const tally = { allowed: 0, denied: 0 };
  const disagreements: string[] = [];
  const questions = world.catalog.data.permissions.map((permission) => ({ permission }));
  for (const at of world.times.filter((time) => time >= issuedAt)) {
    for (const place of world.places) {
      const inside = bases.some(
        (base) => base === "/" || place === base || place.startsWith(`${base}/`),
      );
      for (const question of questions) {
        const now = () => at * 1000;
        const carried = could(world.catalog, grants, { ...question, place }, { now });
        const context = { subject, at, place, question };
        if (!inside) {
          if (carried.covered || carried.allowed || carried.by !== undefined) {
            disagreements.push(`covered outside: ${JSON.stringify(context)}`);
          }
          continue;
        }
        const fresh = ask(world.catalog, read, { ...question, place }, { now });
        const [one, other] = [JSON.stringify(summary(fresh)), JSON.stringify(summary(carried))];
        if (one !== other) disagreements.push(`${JSON.stringify(context)}: ${one} != ${other}`);
        tally[fresh.allowed ? "allowed" : "denied"]++;
      }
    }
  }
  return {
    disagreements: disagreements.slice(0, 5),
    allowed: tally.allowed > 0,
    denied: tally.denied > 0,
  };
}

const AGREE_BOTH = { disagreements: [], allowed: true, denied: true };

function summary(decision: Decision) {
  return {
    allowed: decision.allowed,
    covered: decision.covered,
    by: decision.by === undefined ? "nothing" : decision.by.kind === "deny" ? "deny" : "gives",
  };
}

const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";

describe("a workspace of pages: group exclusions, the subject's own, two groups giving alike", () => {
  const world: World = {
    catalog,
    statements: [
      { kind: "assign", subject: "leads", value: "lead", place: ACME },
      { kind: "assign", subject: "writers", value: "writer", place: ACME },
      { kind: "exclude", subject: "writers", value: "report:write", place: ARCHIVES },
      { kind: "assign", subject: "red", value: "writer", place: ACME },
      { kind: "exclude", subject: "mona", value: "report:write", place: ARCHIVES },
      { kind: "allow", subject: "mona", value: "report:write", place: `${ARCHIVES}/archive=2024` },
      { kind: "allow", subject: "zoe", value: "report:*", place: ACME },
      { kind: "exclude", subject: "zoe", value: "report:write", place: ACME },
      { kind: "allow", subject: "sue", value: "report:write", place: ACME, expiresAt: FRIDAY },
      {
        kind: "exclude",
        subject: "writers",
        value: "chat:*",
        place: `${ARCHIVES}/archive=2019`,
        expiresAt: THURSDAY,
      },
      { kind: "allow", subject: "writers", value: "chat:read", place: ARCHIVES },
    ],
    places: [
      "/",
      ACME,
      ARCHIVES,
      `${ARCHIVES}/archive=2019`,
      `${ARCHIVES}/archive=2024`,
      `${ARCHIVES}/archive=2031`,
      "/org=acme/project=p1",
      "/org=globex",
    ],
    times: LATER,
  };

  it.each([
    ["mona, a lead and a writer", { subject: "mona", groups: ["writers", "leads"] }],
    ["wes, a writer only", { subject: "wes", groups: ["writers"] }],
    [
      "joe, in two groups giving `writer` where one is excluded",
      { subject: "joe", groups: ["writers", "red"] },
    ],
    ["zoe, with her own exclusion at her own place", { subject: "zoe" }],
    ["sue, a writer with her own allow until Friday", { subject: "sue", groups: ["writers"] }],
    [
      "sue, issued for the archives only",
      { subject: "sue", groups: ["writers"], bases: [ARCHIVES] },
    ],
    [
      "hal, joining the leads on Thursday",
      { subject: "hal", groups: ["writers", "leads"], issuedAt: THURSDAY },
    ],
  ])("agrees for %s", (_, asker) => {
    expect(agree(world, asker)).toStrictEqual(AGREE_BOTH);
  });
});

describe("a chat server: bans that lift, exclusions answered lower, wildcard denies", () => {
  const world: World = {
    catalog,
    statements: [
      { kind: "assign", subject: "gil", value: "player", place: "/server=s1" },
      { kind: "deny", subject: "gil", value: "match:join", expiresAt: NEXT_MONDAY },
      { kind: "exclude", subject: "gil", value: "chat:send", place: "/server=s1" },
      { kind: "allow", subject: "gil", value: "chat:send", place: "/server=s1/channel=help" },
      {
        kind: "deny",
        subject: "gil",
        value: "*:send",
        place: "/server=s1/channel=general",
        expiresAt: FRIDAY,
      },
      { kind: "deny", subject: "trolls", value: "*", place: "/server=s1/channel=nsfw" },
      {
        kind: "assign",
        subject: "mods",
        value: "player",
        place: "/server=s1",
        expiresAt: SATURDAY,
      },
      { kind: "exclude", subject: "mods", value: "*:read", place: "/server=s1/channel=help" },
    ],
    places: [
      "/",
      "/server=s1",
      "/server=s1/channel=help",
      "/server=s1/channel=general",
      "/server=s1/channel=nsfw",
      "/server=s2",
    ],
    times: WEEK_AFTER,
  };

  it.each([
    ["gil, alone", { subject: "gil" }],
    ["gil, a troll and a moderator", { subject: "gil", groups: ["trolls", "mods"] }],
    ["ivy, a moderator", { subject: "ivy", groups: ["mods"] }],
    [
      "gil, issued for one channel",
      { subject: "gil", groups: ["mods"], bases: ["/server=s1/channel=general"] },
    ],
  ])("agrees for %s", (_, asker) => {
    expect(agree(world, asker)).toStrictEqual(AGREE_BOTH);
  });
});

describe("a shared drive: stored roles, statements above and under a base, a share that ends", () => {
  const drive = "/drive=d1";
  const world: World = {
    catalog,
    statements: [
      { kind: "assign", subject: "marketing", value: "viewer", place: drive },
      {
        kind: "assign",
        subject: "marketing",
        value: "drive-editor",
        place: `${drive}/folder=brand`,
      },
      { kind: "assign", subject: "pat", value: "reviewer", place: `${drive}/folder=legal` },
      { kind: "assign", subject: "pat", value: "drive-editor", place: "/drive=d2" },
      { kind: "assign", subject: "pat", value: "missing", place: drive },
      { kind: "assign", subject: "pat", value: "broken", place: drive },
      { kind: "assign", subject: "pat", value: "looped", place: drive },
      { kind: "assign", subject: "sue", value: "circle" },
      {
        kind: "allow",
        subject: "sue",
        value: "file:read",
        place: `${drive}/folder=legal/file=contract`,
        expiresAt: MONDAY + 2 * HOUR,
      },
      { kind: "allow", subject: "pat", value: "limited-file:read", place: `${drive}/folder=board` },
      { kind: "deny", subject: "pat", value: "file:write", place: "/", expiresAt: THURSDAY },
      { kind: "deny", subject: "marketing", value: "report:list" },
      { kind: "allow", subject: "pat", value: "report:read", place: ACME },
      {
        kind: "exclude",
        subject: "marketing",
        value: "file:read",
        place: `${drive}/folder=brand/folder=old`,
      },
    ],
    roles: [
      { name: "drive-editor", entries: ["viewer", "file:write", "-report:read"] },
      { name: "reviewer", entries: ["drive-editor", "report:read"] },
      { name: "broken", entries: ["ghost"] },
      { name: "looped", entries: ["file:read", "-circle"] },
      { name: "circle", entries: ["looped"] },
      { name: "viewer", entries: ["*"] },
    ],
    places: [
      "/",
      drive,
      `${drive}/folder=brand`,
      `${drive}/folder=brand/folder=old`,
      `${drive}/folder=legal`,
      `${drive}/folder=legal/file=contract`,
      `${drive}/folder=board`,
      "/drive=d2",
      ACME,
    ],
    times: LATER,
  };

  it.each([
    ["pat, in marketing", { subject: "pat", groups: ["marketing"] }],
    ["pat, issued for the drive only", { subject: "pat", groups: ["marketing"], bases: [drive] }],
    [
      "sue, sharing one file for two hours",
      { subject: "sue", groups: ["marketing"], bases: [`${drive}/folder=legal`] },
    ],
    [
      "sue, issued for two drives",
      { subject: "sue", groups: ["marketing"], bases: [drive, "/drive=d2"] },
    ],
  ])("agrees for %s", (_, asker) => {
    expect(agree(world, asker)).toStrictEqual(AGREE_BOTH);
  });
});

describe("a cloud account tree: `*` at the root and denies on a members group", () => {
  const world: World = {
    catalog,
    statements: [
      { kind: "allow", subject: "owner", value: "*" },
      { kind: "allow", subject: "deploy", value: "*", place: "/" },
      { kind: "deny", subject: "members", value: "audit-log:delete", place: ACME },
      { kind: "allow", subject: "tom", value: "*", place: ACME },
      { kind: "deny", subject: "members", value: "report:write", place: ACME, expiresAt: FRIDAY },
      { kind: "deny", subject: "owner", value: "report:read", place: ACME },
      { kind: "exclude", subject: "owner", value: "*", place: ARCHIVES },
      { kind: "deny", subject: "staff", value: "access:manage" },
      { kind: "exclude", subject: "staff", value: "event:*", place: ACME },
      { kind: "assign", subject: "staff", value: "lead" },
      { kind: "allow", subject: "temp", value: "*", expiresAt: THURSDAY },
      { kind: "deny", subject: "temp", value: "report:read", place: ACME },
    ],
    places: ["/", ACME, ARCHIVES, "/org=globex"],
    times: LATER,
  };

  it.each([
    ["tom, an administrator in the members group", { subject: "tom", groups: ["members"] }],
    ["a staff member", { subject: "kim", groups: ["staff"] }],
    ["a temporary `*` that ends on Thursday", { subject: "temp" }],
    ["tom, issued for the organisation", { subject: "tom", groups: ["members"], bases: [ACME] }],
    [
      "the owner, allowed `*` at the root, denied and excluded by name",
      { subject: "owner", groups: ["members"] },
    ],
    [
      "the deploy job, allowed `*` at the root through a group, in the staff group",
      { subject: "job", groups: ["staff", "deploy"] },
    ],
  ])("agrees for %s", (_, asker) => {
    expect(agree(world, asker)).toStrictEqual(AGREE_BOTH);
  });

  it("agrees for a newcomer to the members group, whom nothing gives anything", () => {
    expect(agree(world, { subject: "new", groups: ["members"] })).toStrictEqual({
      ...AGREE_BOTH,
      allowed: false,
    });
  });
});

describe("implications and wildcards", () => {
  const world: World = {
    catalog,
    statements: [
      { kind: "assign", subject: "alice", value: "analyst", place: ACME },
      { kind: "assign", subject: "bob", value: "analyst", place: ACME },
      { kind: "deny", subject: "bob", value: "report:read", place: ACME },
      { kind: "assign", subject: "cy", value: "support", place: ACME },
      { kind: "allow", subject: "cy", value: "*:read", place: "/org=globex" },
      { kind: "exclude", subject: "cy", value: "*:read", place: "/org=globex/unit=u1" },
      { kind: "allow", subject: "cy", value: "report:write", place: "/org=globex/unit=u1" },
      { kind: "exclude", subject: "readers", value: "report:list", place: "/org=globex" },
      { kind: "allow", subject: "readers", value: "report:*" },
      {
        kind: "deny",
        subject: "readers",
        value: "event:read",
        place: "/org=globex",
        expiresAt: SATURDAY,
      },
      { kind: "assign", subject: "readers", value: "lead", place: ACME },
    ],
    places: ["/", ACME, "/org=acme/report=q3", "/org=globex", "/org=globex/unit=u1"],
    times: LATER,
  };

  it.each([
    ["alice", { subject: "alice" }],
    ["bob, denied what writing reads", { subject: "bob" }],
    ["cy, everything readable but reports", { subject: "cy", groups: ["readers"] }],
    ["a reader", { subject: "dee", groups: ["readers"] }],
  ])("agrees for %s", (_, asker) => {
    expect(agree(world, asker)).toStrictEqual(AGREE_BOTH);
  });
});

describe("a flat application", () => {
  const flat = defineCatalog({
    permissions: ["post:read", "post:draft", "post:publish", "access:manage"],
    implies: { "post:publish": ["post:read"] },
    presets: { viewer: ["post:read"], editor: ["post:*"] },
    places: false,
  });
  const world: World = {
    catalog: flat,
    statements: [
      { kind: "allow", subject: "ed", value: "*" },
      { kind: "assign", subject: "ed", value: "viewer" },
      { kind: "deny", subject: "ed", value: "post:read" },
      { kind: "assign", subject: "assistant", value: "editor", expiresAt: NEXT_MONDAY },
      { kind: "exclude", subject: "assistant", value: "post:publish" },
      { kind: "deny", subject: "bots", value: "post:draft", expiresAt: FRIDAY },
      { kind: "allow", subject: "bots", value: "post:draft" },
    ],
    places: ["/"],
    times: WEEK_AFTER,
  };

  it("agrees for ed, allowed `*` at the root and denied by name", () => {
    expect(agree(world, { subject: "ed", groups: ["bots"] })).toStrictEqual(AGREE_BOTH);
  });

  it("agrees for the assistant, a bot whose role ends next Monday", () => {
    expect(agree(world, { subject: "assistant", groups: ["bots"] })).toStrictEqual(AGREE_BOTH);
  });
});
