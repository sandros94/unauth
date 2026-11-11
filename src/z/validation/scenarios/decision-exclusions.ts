import type { CatalogData } from "../../catalog.ts";
import type { Scenario } from "../types.ts";
import { MONDAY, allow, ask, assign, deny, exclude } from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";
const HR = "/org=acme/unit=hr";
const U1 = "/org=acme/unit=u1";
const SERVER = "/server=s1";
const ARCHIVES = "/org=acme/area=archives";

const chain: CatalogData = {
  permissions: ["report:list", "report:read", "report:write", "invoice:read", "invoice:pay"],
  implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
};

export const decisionExclusionScenarios: readonly Scenario[] = [
  {
    id: "decision/exclusion-wins-at-its-place",
    title:
      "A muted member: an exclusion beats an allow at its own place, whoever the allow is about, and yields lower down",
    proves: ["D4", "D7"],
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
    proves: ["D7", "D4"],
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
    proves: ["D4", "D3"],
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
    proves: ["D1", "D5"],
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
    proves: ["D2", "D3", "D4"],
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
    proves: ["D5", "D1"],
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
];
