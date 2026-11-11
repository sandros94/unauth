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
  write,
} from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";
const FINANCE = "/org=acme/unit=finance";
const ARCHIVE_2019 = "/org=acme/area=archives/archive=2019";

const reports: CatalogData = {
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { writer: ["report:read", "report:write"] },
  places: { "/": ["org"], "org": ["area"], "area": ["archive"] },
};

export const decisionScenarios: readonly Scenario[] = [
  {
    id: "decision/nothing-stated",
    title: "A new employee is denied everything until someone allows her something",
    proves: ["D1"],
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
    proves: ["D2"],
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
    proves: ["D3"],
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
    proves: ["D4", "D2"],
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
    proves: ["D5"],
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
];
