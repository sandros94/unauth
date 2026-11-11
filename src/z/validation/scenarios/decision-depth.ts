import type { CatalogData } from "../../catalog.ts";
import type { Scenario } from "../types.ts";
import {
  DAY,
  FRIDAY_MIDNIGHT,
  HOUR,
  MONDAY,
  allow,
  ask,
  deny,
  exclude,
  write,
} from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";

const drive: CatalogData = {
  permissions: ["file:read", "file:write"],
  places: { "/": ["drive"], "drive": ["folder"], "folder": ["folder"] },
};

export const decisionDepthScenarios: readonly Scenario[] = [
  {
    id: "decision/one-time",
    title: "An allow until 17:00 counts at 16:59:59 and not at 17:00, beside one with no end",
    proves: ["D6"],
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
    proves: ["D7", "D2"],
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
    id: "decision/permanent-manager",
    title:
      "The owner acts through a deny and an exclusion about her; a time-limited or narrower admin does not",
    proves: ["D9"],
    catalog: {
      permissions: ["report:read", "report:write", "access:manage"],
      manager: "access:manage",
      places: { "/": ["org"], "org": ["unit"] },
    },
    statements: [
      allow("owner", "*"),
      deny("owner", "report:read", ACME),
      exclude("owner", "report:*", ACME),
      allow("temp-admin", "*", undefined, FRIDAY_MIDNIGHT),
      deny("temp-admin", "report:read", ACME),
      allow("org-admin", "*", ACME),
      deny("org-admin", "report:read", "/org=acme/unit=u1"),
      allow("deploy-bots", "*", "/"),
      deny("staff", "access:manage"),
      deny("ci", "report:write", ACME),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "owner", permission: "report:read", place: "/org=acme/unit=u1" },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(MONDAY, { subject: "owner", permission: "report:write", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "temp-admin", permission: "report:read", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "temp-admin", permission: "report:write", place: ACME }, "allowed"),
      ask(
        MONDAY,
        { subject: "org-admin", permission: "report:read", place: "/org=acme/unit=u1" },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "ci",
          groups: ["deploy-bots", "staff"],
          permission: "access:manage",
          place: ACME,
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "ci",
          groups: ["deploy-bots", "staff"],
          permission: "report:write",
          place: ACME,
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      write({
        remove: [{ kind: "allow", subject: "owner", value: "*" }],
        save: [allow("owner", "report:*")],
      }),
      ask(
        MONDAY + HOUR,
        { subject: "owner", permission: "report:read", place: "/org=acme/unit=u1" },
        "denied",
        { issuedAt: MONDAY + HOUR },
      ),
      ask(MONDAY + HOUR, { subject: "owner", permission: "report:write", place: ACME }, "denied", {
        issuedAt: MONDAY + HOUR,
      }),
      ask(
        MONDAY + HOUR,
        { subject: "owner", permission: "report:write", place: "/org=globex" },
        "allowed",
      ),
    ],
  },
];
