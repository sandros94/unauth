import type { CatalogData } from "../../catalog.ts";
import type { Scenario } from "../types.ts";
import {
  DAY,
  FRIDAY_MIDNIGHT,
  HOUR,
  MONDAY,
  allow,
  ask,
  assign,
  deny,
  exclude,
  hand,
  issue,
  read,
  write,
} from "./_internal/steps.ts";

const ACME = "/org=acme";
const FINANCE = "/org=acme/unit=finance";
const ARCHIVE_2019 = "/org=acme/area=archives/archive=2019";
const ARCHIVES = "/org=acme/area=archives";
const HR = "/org=acme/unit=hr";
const U1 = "/org=acme/unit=u1";
const SERVER = "/server=s1";
const GLOBEX = "/org=globex";
const NEWS = "/site=blog/section=news";

const TUESDAY = MONDAY + DAY;
const SATURDAY = MONDAY + 5 * DAY;

const reports: CatalogData = {
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { writer: ["report:read", "report:write"] },
  places: { "/": ["org"], "org": ["area"], "area": ["archive"] },
};

const docs: CatalogData = {
  permissions: ["doc:read", "doc:write"],
  implies: { "doc:write": ["doc:read"] },
  places: { "/": ["org"], "org": ["area"] },
};

const drive: CatalogData = {
  permissions: ["file:read", "file:write"],
  places: { "/": ["drive"], "drive": ["folder"], "folder": ["folder"] },
};

const chain: CatalogData = {
  permissions: ["report:list", "report:read", "report:write", "invoice:read", "invoice:pay"],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
};

const managedReports: CatalogData = {
  permissions: ["access:manage", "report:list", "report:read", "report:write"],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
  places: { "/": ["org"], "org": ["unit"] },
};

const posts: CatalogData = {
  permissions: ["post:read", "post:edit", "post:approve"],
  presets: { editor: ["post:read", "post:edit"] },
  places: { "/": ["site"], "site": ["section"] },
};

const designWrites = allow("design", "doc:write", ACME);
const contractorsBanned = deny("contractors", "doc:read", ARCHIVES);
const annReads = allow("ann", "doc:read", ACME);

export const decisionScenarios: readonly Scenario[] = [
  {
    id: "decision/nothing-stated",
    title: "A new employee is denied everything until someone allows her something",
    proves: ["G1"],
    catalog: { permissions: ["report:read", "report:write"] },
    statements: [allow("jon", "report:read", ACME), exclude("ivy", "report:write", ACME)],
    steps: [
      ask(MONDAY, { subject: "ivy", permission: "report:read", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "ivy", permission: "report:read" }, "denied"),
      ask(MONDAY, { subject: "ivy", permission: "report:write", place: ACME }, "denied"),
      write({ save: [allow("ivy", "report:read", ACME)] }),
      ask(MONDAY + HOUR, { subject: "ivy", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY + HOUR,
      }),
      ask(MONDAY + HOUR, { subject: "ivy", permission: "report:write", place: ACME }, "denied"),
    ],
  },
  {
    id: "decision/group-deny-from-above",
    title:
      "A ban on contractors approving invoices reaches a contractor allowed it in finance, until it ends",
    proves: ["G2"],
    catalog: {
      permissions: ["invoice:read", "invoice:approve"],
      presets: { approver: ["invoice:read", "invoice:approve"] },
      places: { "/": ["org"], "org": ["unit"] },
    },
    statements: [
      assign("finance-team", "approver", FINANCE),
      deny("contractors", "invoice:approve", ACME, FRIDAY_MIDNIGHT),
      allow("bob", "invoice:approve", FINANCE),
    ],
    steps: [
      ask(
        MONDAY,
        {
          subject: "bob",
          groups: ["finance-team", "contractors"],
          permission: "invoice:approve",
          place: FINANCE,
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "bob",
          groups: ["finance-team", "contractors"],
          permission: "invoice:read",
          place: FINANCE,
        },
        "allowed",
      ),
      ask(
        MONDAY,
        {
          subject: "kim",
          groups: ["finance-team"],
          permission: "invoice:approve",
          place: FINANCE,
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY + 5 * DAY,
        {
          subject: "bob",
          groups: ["finance-team", "contractors"],
          permission: "invoice:approve",
          place: FINANCE,
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
    ],
  },
  {
    id: "decision/implication-alice-bob",
    title: "Two analysts, one denied reading: writing goes with reading, listing stays",
    proves: ["G3"],
    catalog: {
      permissions: ["report:list", "report:read", "report:write"],
      implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
      presets: { analyst: ["report:write"] },
    },
    statements: [
      assign("alice", "analyst", ACME),
      assign("bob", "analyst", ACME),
      deny("bob", "report:read", ACME),
    ],
    steps: (
      [
        ["alice", "report:write", "allowed"],
        ["alice", "report:read", "allowed"],
        ["alice", "report:list", "allowed"],
        ["bob", "report:write", "denied"],
        ["bob", "report:read", "denied"],
        ["bob", "report:list", "allowed"],
      ] as const
    ).map(([subject, permission, expect]) =>
      ask(MONDAY, { subject, permission, place: "/org=acme/report=q3" }, expect, {
        issuedAt: MONDAY,
      }),
    ),
  },
  {
    id: "decision/one-more-group",
    title: "Joining the auditors takes nothing from Wes, until the auditors are denied",
    proves: ["G4", "G2"],
    catalog: reports,
    statements: [
      assign("writers", "writer", ACME),
      exclude("writers", "report:write", "/org=acme/area=archives"),
      allow("wes", "report:write", ACME),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "wes", groups: ["writers"], permission: "report:write", place: ARCHIVE_2019 },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "uma", groups: ["writers"], permission: "report:write", place: ARCHIVE_2019 },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "uma", groups: ["writers"], permission: "report:read", place: ARCHIVE_2019 },
        "allowed",
      ),
      write({ save: [exclude("auditors", "report:write", ACME)] }),
      ask(
        MONDAY + HOUR,
        {
          subject: "wes",
          groups: ["writers", "auditors"],
          permission: "report:write",
          place: ARCHIVE_2019,
        },
        "allowed",
        { issuedAt: MONDAY + HOUR },
      ),
      write({ save: [deny("auditors", "report:write", "/org=acme/area=archives")] }),
      ask(
        MONDAY + 2 * HOUR,
        {
          subject: "wes",
          groups: ["writers", "auditors"],
          permission: "report:write",
          place: ARCHIVE_2019,
        },
        "denied",
        { issuedAt: MONDAY + 2 * HOUR },
      ),
      ask(
        MONDAY + 2 * HOUR,
        {
          subject: "wes",
          groups: ["writers", "auditors"],
          permission: "report:write",
          place: "/org=acme/area=projects",
        },
        "allowed",
      ),
      ask(
        MONDAY + 3 * HOUR,
        { subject: "wes", groups: ["writers"], permission: "report:write", place: ARCHIVE_2019 },
        "allowed",
      ),
    ],
  },
  {
    id: "decision/elsewhere-and-unrelated",
    title: "Denies at other places and on other permissions leave Alice's reading alone",
    proves: ["G5"],
    catalog: {
      permissions: ["report:read", "report:write", "billing:read"],
      implies: { "report:write": ["report:read"] },
    },
    statements: [
      allow("alice", "report:read", ACME),
      deny("alice", "report:read", "/org=acm"),
      deny("alice", "report:read", "/org=globex"),
      deny("alice", "report:read", "/org=acme/unit=u7"),
      deny("alice", "report:write", ACME),
      deny("alice", "billing:read", ACME),
      exclude("alice", "billing:read", ACME),
      deny("bob", "report:read", ACME),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "alice", permission: "report:read", place: "/org=acme/unit=u3" },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "alice", permission: "report:read", place: ACME }, "allowed"),
      ask(
        MONDAY,
        { subject: "alice", permission: "report:read", place: "/org=acme/unit=u7" },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "alice", permission: "report:read", place: "/org=acme-x" }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(
        MONDAY,
        { subject: "alice", permission: "report:write", place: "/org=acme/unit=u3" },
        "denied",
      ),
    ],
  },
  {
    id: "decision/handed-statements-all-apply",
    title:
      "An application hands over statements about teams Ann is not in: the engine counts each as one of her groups'",
    proves: ["G1", "G2"],
    catalog: docs,
    statements: [designWrites, contractorsBanned, annReads],
    steps: [
      ask(MONDAY, { subject: "ann", permission: "doc:write", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      hand(MONDAY, "ann", [designWrites], { permission: "doc:write", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      hand(MONDAY, "ann", [designWrites], { permission: "doc:read", place: ARCHIVES }, "allowed"),
      ask(MONDAY, { subject: "ann", permission: "doc:read", place: ARCHIVES }, "allowed", {
        issuedAt: MONDAY,
      }),
      hand(
        MONDAY,
        "ann",
        [annReads, contractorsBanned],
        { permission: "doc:read", place: ARCHIVES },
        "denied",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [annReads, contractorsBanned],
        { permission: "doc:read", place: ACME },
        "allowed",
        { issuedAt: MONDAY },
      ),
    ],
  },
  {
    id: "decision/handed-exclusion-takes-its-own",
    title:
      "A handed exclusion about another identifier takes out what that identifier gave and nothing else, compared byte by byte",
    proves: ["G4"],
    catalog: docs,
    steps: [
      hand(
        MONDAY,
        "ann",
        [designWrites, exclude("design", "doc:write", ARCHIVES)],
        { permission: "doc:write", place: ARCHIVES },
        "denied",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [designWrites, exclude("design", "doc:write", ARCHIVES)],
        { permission: "doc:write", place: ACME },
        "allowed",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [designWrites, exclude("design", "doc:write", ARCHIVES), allow("ops", "doc:write", ACME)],
        { permission: "doc:write", place: ARCHIVES },
        "allowed",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [designWrites, exclude("design", "doc:write", ARCHIVES), allow("ann", "doc:write", ACME)],
        { permission: "doc:write", place: ARCHIVES },
        "allowed",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [designWrites, exclude("Design", "doc:write", ARCHIVES)],
        { permission: "doc:write", place: ARCHIVES },
        "allowed",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [designWrites, allow("ops", "doc:write", ACME), exclude("ann", "doc:write", ARCHIVES)],
        { permission: "doc:write", place: ARCHIVES },
        "denied",
        { issuedAt: MONDAY },
      ),
    ],
  },
  {
    id: "decision/handed-group-left-out",
    title:
      "Ann is a contractor and a designer: with a group's statements left out, its deny blocks nothing and its allow gives nothing",
    proves: ["G2", "G1"],
    catalog: docs,
    statements: [designWrites, contractorsBanned, annReads],
    steps: [
      ask(
        MONDAY,
        {
          subject: "ann",
          groups: ["contractors", "design"],
          permission: "doc:read",
          place: ARCHIVES,
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [annReads, designWrites],
        { permission: "doc:read", place: ARCHIVES },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "ann", groups: ["contractors", "design"], permission: "doc:write", place: ACME },
        "allowed",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [annReads, contractorsBanned],
        { permission: "doc:write", place: ACME },
        "denied",
        { issuedAt: MONDAY },
      ),
    ],
  },
  {
    id: "decision/one-time",
    title: "An allow until 17:00 counts at 16:59:59 and not at 17:00, beside one with no end",
    proves: ["G6"],
    catalog: { permissions: ["report:read", "report:export"] },
    statements: [
      allow("kai", "report:read", ACME),
      allow("kai", "report:export", ACME, MONDAY + 8 * HOUR),
    ],
    steps: [
      ask(
        MONDAY + 8 * HOUR - 1,
        { subject: "kai", permission: "report:read", place: ACME },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY + 8 * HOUR - 1,
        { subject: "kai", permission: "report:export", place: ACME },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY + 8 * HOUR,
        { subject: "kai", permission: "report:export", place: ACME },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY + 8 * HOUR,
        { subject: "kai", permission: "report:export", place: ACME },
        "denied",
      ),
      ask(
        MONDAY + 8 * HOUR,
        { subject: "kai", permission: "report:read", place: ACME },
        "allowed",
        { issuedAt: MONDAY },
      ),
    ],
  },
  {
    id: "decision/depth-ranks-only-exclusions",
    title:
      "In nested folders a ban at the top beats an allow deep down, while an exclusion yields to one",
    proves: ["G7", "G2"],
    catalog: drive,
    statements: [
      allow("pia", "file:write", "/drive=d1/folder=a/folder=b"),
      deny("pia", "file:write", "/drive=d1"),
      allow("pia", "file:read", "/drive=d1"),
      deny("pia", "file:read", "/drive=d1/folder=a/folder=b"),
      allow("pia", "file:read", "/drive=d1/folder=c", MONDAY + DAY),
      allow("leo", "file:write", "/drive=d1"),
      exclude("leo", "file:write", "/drive=d1/folder=a"),
      allow("leo", "file:write", "/drive=d1/folder=a/folder=b"),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "pia", permission: "file:write", place: "/drive=d1/folder=a/folder=b" },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "pia", permission: "file:read", place: "/drive=d1/folder=a/folder=b" },
        "denied",
      ),
      ask(
        MONDAY,
        { subject: "pia", permission: "file:read", place: "/drive=d1/folder=a" },
        "allowed",
      ),
      ask(
        MONDAY + 2 * DAY,
        { subject: "pia", permission: "file:read", place: "/drive=d1/folder=c" },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY + 2 * DAY,
        { subject: "leo", permission: "file:write", place: "/drive=d1/folder=a" },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY + 2 * DAY,
        { subject: "leo", permission: "file:write", place: "/drive=d1/folder=a/folder=b" },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY + 2 * DAY,
        { subject: "leo", permission: "file:write", place: "/drive=d1/folder=a/folder=z" },
        "denied",
      ),
      ask(
        MONDAY + 2 * DAY,
        { subject: "leo", permission: "file:write", place: "/drive=d1" },
        "allowed",
      ),
    ],
  },
  {
    id: "decision/exclusion-wins-at-its-place",
    title:
      "A muted member: an exclusion beats an allow at its own place, whoever the allow is about, and yields lower down",
    proves: ["G4", "G7"],
    catalog: {
      permissions: ["chat:read", "chat:send"],
      places: { "/": ["server"], "server": ["channel"] },
    },
    statements: [
      allow("gil", "chat:send", SERVER),
      exclude("gil", "chat:send", SERVER),
      allow("mods", "chat:send", "/server=s1/channel=c2"),
      exclude("gil", "chat:send", "/server=s1/channel=c2"),
      allow("helpers", "chat:send", "/server=s1/channel=help"),
      allow("mods", "chat:read", SERVER),
      exclude("mods", "chat:read", SERVER),
      allow("nia", "chat:read", SERVER),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "gil", groups: ["helpers", "mods"], permission: "chat:send", place: SERVER },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        {
          subject: "gil",
          groups: ["helpers", "mods"],
          permission: "chat:send",
          place: "/server=s1/channel=lobby",
        },
        "denied",
      ),
      ask(
        MONDAY,
        {
          subject: "gil",
          groups: ["helpers", "mods"],
          permission: "chat:send",
          place: "/server=s1/channel=c2",
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "gil",
          groups: ["helpers", "mods"],
          permission: "chat:send",
          place: "/server=s1/channel=help",
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "gil",
          groups: ["helpers", "mods"],
          permission: "chat:read",
          place: "/server=s1/channel=lobby",
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "nia", groups: ["mods"], permission: "chat:read", place: SERVER },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "ona", groups: ["mods"], permission: "chat:read", place: SERVER },
        "denied",
      ),
    ],
  },
  {
    id: "decision/exclusion-group-given-back-lower",
    title:
      "Writers are excluded from writing in the archives and allowed again in the 2024 archive",
    proves: ["G7", "G4"],
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:write": ["report:read"] },
      presets: { writer: ["report:read", "report:write"] },
      places: { "/": ["org"], "org": ["area"], "area": ["archive"] },
    },
    statements: [
      assign("writers", "writer", ACME),
      exclude("writers", "report:write", ARCHIVES),
      allow("writers", "report:write", `${ARCHIVES}/archive=2024`),
    ],
    steps: [
      ask(
        MONDAY,
        {
          subject: "wes",
          groups: ["writers"],
          permission: "report:write",
          place: `${ARCHIVES}/archive=2024`,
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "wes",
          groups: ["writers"],
          permission: "report:write",
          place: `${ARCHIVES}/archive=2019`,
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "wes", groups: ["writers"], permission: "report:write", place: ARCHIVES },
        "denied",
      ),
      ask(
        MONDAY,
        {
          subject: "wes",
          groups: ["writers"],
          permission: "report:read",
          place: `${ARCHIVES}/archive=2019`,
        },
        "allowed",
      ),
    ],
  },
  {
    id: "decision/exclusion-reaches-what-includes-it",
    title:
      "Excluding reading in HR also takes writing, and listing too when writing was all that gave it; a deny of reading leaves listing",
    proves: ["G4", "G3"],
    catalog: {
      permissions: ["report:list", "report:read", "report:write"],
      implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
      presets: { analyst: ["report:write"], reporter: ["report:list", "report:write"] },
    },
    statements: [
      assign("ana", "analyst", ACME),
      exclude("ana", "report:read", HR),
      assign("ben", "reporter", ACME),
      exclude("ben", "report:read", HR),
      assign("cal", "analyst", ACME),
      deny("cal", "report:read", HR),
    ],
    steps: (
      [
        ["ana", "report:write", HR, "denied"],
        ["ana", "report:read", HR, "denied"],
        ["ana", "report:list", HR, "denied"],
        ["ana", "report:list", "/org=acme/unit=sales", "allowed"],
        ["ben", "report:list", HR, "allowed"],
        ["ben", "report:write", HR, "denied"],
        ["cal", "report:list", HR, "allowed"],
        ["cal", "report:write", HR, "denied"],
      ] as const
    ).map(([subject, permission, place, expect]) =>
      ask(MONDAY, { subject, permission, place }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "decision/wildcard-allows",
    title: "Allows of every read, of every report action and of everything at one organisation",
    proves: ["G1", "G5"],
    catalog: chain,
    statements: [
      allow("ola", "*:read", ACME),
      allow("pim", "report:*", ACME),
      allow("quin", "*", ACME),
    ],
    steps: (
      [
        ["ola", "invoice:read", U1, "allowed"],
        ["ola", "report:list", U1, "allowed"],
        ["ola", "report:write", U1, "denied"],
        ["ola", "invoice:pay", U1, "denied"],
        ["pim", "report:write", U1, "allowed"],
        ["pim", "invoice:read", U1, "denied"],
        ["quin", "invoice:pay", U1, "allowed"],
        ["quin", "invoice:pay", "/org=globex", "denied"],
      ] as const
    ).map(([subject, permission, place, expect]) =>
      ask(MONDAY, { subject, permission, place }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "decision/wildcard-denies-and-exclusions",
    title:
      "In HR: a deny of every read stops writing, an exclusion of every invoice action spares reports, a deny of everything stops all",
    proves: ["G2", "G3", "G4"],
    catalog: chain,
    statements: [
      allow("pim", "report:*", ACME),
      deny("pim", "*:read", HR),
      allow("quin", "*", ACME),
      exclude("quin", "invoice:*", HR),
      allow("rex", "report:read"),
      deny("rex", "*", HR),
    ],
    steps: (
      [
        ["pim", "report:write", HR, "denied"],
        ["pim", "report:list", HR, "allowed"],
        ["pim", "report:write", U1, "allowed"],
        ["quin", "invoice:pay", HR, "denied"],
        ["quin", "invoice:read", HR, "denied"],
        ["quin", "report:write", HR, "allowed"],
        ["rex", "report:list", HR, "denied"],
        ["rex", "report:read", U1, "allowed"],
      ] as const
    ).map(([subject, permission, place, expect]) =>
      ask(MONDAY, { subject, permission, place }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "decision/inert-unknown-permissions",
    title:
      "Statements naming permissions the catalog no longer declares give, block and take out nothing",
    proves: ["G5", "G1"],
    catalog: { permissions: ["report:read", "report:write"] },
    statements: [
      allow("sam", "report:read", ACME),
      deny("sam", "legacy:export", ACME),
      deny("sam", "invoice:*", ACME),
      deny("sam", "*:approve", ACME),
      exclude("sam", "*:archive", ACME),
      exclude("sam", "legacy:export", ACME),
      allow("tia", "legacy:export", ACME),
      allow("tia", "invoice:*", ACME),
      allow("tia", "*:approve", ACME),
    ],
    steps: [
      ask(MONDAY, { subject: "sam", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "tia", permission: "report:read", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "tia", permission: "report:write", place: ACME }, "denied"),
      ask(
        MONDAY,
        { subject: "sam", permission: "legacy:export", place: ACME },
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "tia", permission: "invoice:pay", place: ACME },
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
      ),
    ],
  },
  {
    id: "decision/owner-denied-until-friday",
    title:
      "The owner, allowed everything at the root for good, is kept out of acme's reports until Friday and later out of globex",
    proves: ["G2", "G3", "G8"],
    catalog: managedReports,
    statements: [allow("owner", "*"), deny("owner", "report:read", ACME, FRIDAY_MIDNIGHT)],
    steps: [
      issue(MONDAY, "owner", "owner"),
      ask(TUESDAY, { subject: "owner", permission: "report:read", place: U1 }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(TUESDAY, { subject: "owner", permission: "report:write", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(TUESDAY, { subject: "owner", permission: "report:list", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(TUESDAY, { subject: "owner", permission: "report:read", place: GLOBEX }, "allowed", {
        issuedAt: MONDAY,
      }),
      read(TUESDAY, "owner", { permission: "report:read", place: U1 }, "denied"),
      read(SATURDAY, "owner", { permission: "report:read", place: U1 }, "allowed"),
      ask(SATURDAY, { subject: "owner", permission: "report:write", place: U1 }, "allowed", {
        issuedAt: MONDAY,
      }),
      write({ save: [deny("owner", "*", GLOBEX)] }),
      ask(
        SATURDAY + HOUR,
        { subject: "owner", permission: "report:list", place: GLOBEX },
        "denied",
        { issuedAt: SATURDAY + HOUR },
      ),
      ask(
        SATURDAY + HOUR,
        { subject: "owner", permission: "access:manage", place: `${GLOBEX}/unit=u2` },
        "denied",
        { issuedAt: SATURDAY + HOUR },
      ),
      read(SATURDAY + HOUR, "owner", { permission: "report:list", place: GLOBEX }, "allowed"),
    ],
  },
  {
    id: "decision/owner-excluded-at-acme",
    title:
      "The owner is excluded from acme's reports and allowed to read them in one unit: only that reading comes back",
    proves: ["G4", "G7", "G8"],
    catalog: managedReports,
    statements: [
      allow("owner", "*"),
      exclude("owner", "report:*", ACME),
      allow("owner", "report:read", U1),
    ],
    steps: [
      ask(MONDAY, { subject: "owner", permission: "report:list", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "owner", permission: "report:read", place: U1 }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "owner", permission: "report:write", place: U1 }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "owner", permission: "access:manage", place: U1 }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "owner", permission: "report:write", place: GLOBEX }, "allowed", {
        issuedAt: MONDAY,
      }),
    ],
  },
  {
    id: "decision/admins-group-restricted",
    title:
      "Platform admins hold everything through their group: a deny on contractors, an exclusion and a deny on the admins reach them",
    proves: ["G2", "G4", "G8"],
    catalog: managedReports,
    statements: [
      allow("platform-admins", "*"),
      allow("vee", "report:write"),
      deny("contractors", "access:manage"),
      exclude("platform-admins", "report:write", ACME),
    ],
    steps: [
      issue(MONDAY, "uri", "uri", { groups: ["platform-admins"] }),
      ask(
        MONDAY,
        {
          subject: "ci",
          groups: ["platform-admins", "contractors"],
          permission: "access:manage",
          place: ACME,
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "uri", groups: ["platform-admins"], permission: "access:manage", place: ACME },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "uri", groups: ["platform-admins"], permission: "report:write", place: U1 },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "uri", groups: ["platform-admins"], permission: "report:read", place: U1 },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "vee", groups: ["platform-admins"], permission: "report:write", place: U1 },
        "allowed",
        { issuedAt: MONDAY },
      ),
      write({ save: [deny("platform-admins", "report:read", GLOBEX)] }),
      ask(
        TUESDAY,
        { subject: "vee", groups: ["platform-admins"], permission: "report:write", place: GLOBEX },
        "denied",
        { issuedAt: TUESDAY },
      ),
      ask(
        TUESDAY,
        { subject: "uri", groups: ["platform-admins"], permission: "report:list", place: GLOBEX },
        "allowed",
        { issuedAt: TUESDAY },
      ),
      read(TUESDAY, "uri", { permission: "report:write", place: U1 }, "denied"),
      read(TUESDAY, "uri", { permission: "report:read", place: GLOBEX }, "allowed"),
    ],
  },
  {
    id: "decision/invalid-questions",
    title: "Questions an application builds wrong are refused, also for the owner",
    proves: [],
    catalog: posts,
    statements: [assign("eva", "editor", "/site=blog"), allow("owner", "*")],
    steps: [
      ask(MONDAY, { subject: "eva", permission: "", place: NEWS }, "ERR_AUTHZ_QUESTION_INVALID", {
        issuedAt: MONDAY,
      }),
      ask(
        MONDAY,
        { subject: "eva", permission: "post:*", place: NEWS },
        "ERR_AUTHZ_QUESTION_INVALID",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "eva", permission: "*", place: NEWS }, "ERR_AUTHZ_QUESTION_INVALID"),
      ask(
        MONDAY,
        { subject: "eva", permission: "post:delete", place: NEWS },
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "eva", permission: "Post:edit", place: NEWS }, "ERR_AUTHZ_MALFORMED", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "owner", permission: "" }, "ERR_AUTHZ_QUESTION_INVALID"),
      ask(MONDAY, { subject: "owner", permission: "post:delete" }, "ERR_AUTHZ_PERMISSION_UNKNOWN"),
      ask(MONDAY, { subject: "owner", permission: "*:*" }, "ERR_AUTHZ_MALFORMED"),
      ask(MONDAY, { subject: "owner", permission: "*" }, "ERR_AUTHZ_QUESTION_INVALID", {
        issuedAt: MONDAY,
      }),
    ],
  },
  {
    id: "decision/structure-folders-anywhere",
    title:
      "A media library whose folders sit under anything, with statements left from an older structure",
    proves: ["G1"],
    catalog: {
      permissions: ["asset:read", "asset:edit"],
      places: { "/": ["library"], "*": ["folder"], "folder": ["asset"] },
    },
    statements: [
      allow("liv", "asset:read", "/library=brand"),
      allow("liv", "asset:edit", "/library=brand/asset=a1"),
      deny("liv", "asset:read", "/team=design"),
    ],
    steps: [
      ask(
        MONDAY,
        {
          subject: "liv",
          permission: "asset:read",
          place: "/library=brand/folder=logos/folder=2026/asset=a1",
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "liv", permission: "asset:read", place: "/folder=inbox" }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(
        MONDAY,
        {
          subject: "liv",
          permission: "asset:edit",
          place: "/library=brand/folder=logos/asset=a1",
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "liv",
          permission: "asset:read",
          place: "/library=brand/folder=f/asset=a1/folder=x",
        },
        "allowed",
      ),
      ask(
        MONDAY,
        { subject: "liv", permission: "asset:read", place: "/library=brand/asset=a1" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "liv", permission: "asset:read", place: "/library=brand/library=old" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
      ),
      ask(
        MONDAY,
        { subject: "liv", permission: "asset:read", place: "/asset=a1" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
      ),
      issue(MONDAY, "outside", "liv", {
        bases: ["/library=brand/asset=a1"],
        expect: "ERR_AUTHZ_PLACE_OUTSIDE",
      }),
      issue(MONDAY, "malformed", "liv", {
        bases: ["/library=brand/"],
        expect: "ERR_AUTHZ_MALFORMED",
      }),
    ],
  },
  {
    id: "decision/structure-none",
    title:
      "A notes app without places refuses every key but the root, and ignores a deny left from its team days",
    proves: ["G1"],
    catalog: {
      permissions: ["note:read", "note:write"],
      presets: { editor: ["note:read", "note:write"] },
      places: false,
    },
    statements: [assign("ed", "editor"), deny("ed", "note:write", "/team=t1")],
    steps: [
      ask(MONDAY, { subject: "ed", permission: "note:write" }, "allowed", { issuedAt: MONDAY }),
      ask(MONDAY, { subject: "ed", permission: "note:write", place: "/" }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "fay", permission: "note:read" }, "denied", { issuedAt: MONDAY }),
      ask(
        MONDAY,
        { subject: "ed", permission: "note:write", place: "/team=t1" },
        "ERR_AUTHZ_PLACE_OUTSIDE",
        {
          issuedAt: MONDAY,
        },
      ),
      issue(MONDAY, "team", "ed", { bases: ["/team=t1"], expect: "ERR_AUTHZ_PLACE_OUTSIDE" }),
      issue(MONDAY, "root", "ed", { bases: ["/"] }),
      read(MONDAY, "root", { permission: "note:read" }, "allowed"),
    ],
  },
  {
    id: "decision/structure-unchecked",
    title:
      "Without a declared structure every canonical key is a place, and a key in another spelling is refused",
    proves: ["G1"],
    catalog: { permissions: ["doc:read"] },
    statements: [allow("gus", "doc:read", "/tenant=t1")],
    steps: [
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=t1/anything=x/deeper=y" },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/account=did:plc:abc" },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(MONDAY, { subject: "gus", permission: "doc:read", place: "/tenant=caf%C3%A9" }, "denied"),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=t1/" },
        "ERR_AUTHZ_MALFORMED",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=caf%c3%a9" },
        "ERR_AUTHZ_MALFORMED",
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "/tenant=t%31" },
        "ERR_AUTHZ_MALFORMED",
      ),
      ask(
        MONDAY,
        { subject: "gus", permission: "doc:read", place: "tenant=t1" },
        "ERR_AUTHZ_MALFORMED",
      ),
      issue(MONDAY, "bad-base", "gus", { bases: ["/Tenant=t1"], expect: "ERR_AUTHZ_MALFORMED" }),
    ],
  },
];
