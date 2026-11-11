import type { Scenario } from "../types.ts";
import { DAY, HOUR, MONDAY, allow, ask, assign, deny } from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";
const PAYMENTS = "/cluster=prod/namespace=payments";
const SEARCH = "/cluster=prod/namespace=search";

export const decisionPlatformScenarios: readonly Scenario[] = [
  {
    id: "decision/one-person-and-an-assistant",
    title: "Ed owns a blog without places and lets his assistant read and draft, then publish",
    proves: ["D1"],
    catalog: {
      permissions: ["post:read", "post:draft", "post:publish", "access:manage"],
      manager: "access:manage",
      places: false,
    },
    statements: [
      allow("ed", "*"),
      allow("assistant", "post:read"),
      allow("assistant", "post:draft"),
    ],
    steps: [
      ask(MONDAY, { subject: "assistant", permission: "post:read" }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "assistant", permission: "post:draft" }, "allowed"),
      ask(MONDAY, { subject: "assistant", permission: "post:publish" }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "ed", permission: "post:publish" }, "allowed", { issuedAt: MONDAY }),
      {
        step: "change",
        at: MONDAY + HOUR,
        author: "ed",
        change: { action: "place", statement: allow("assistant", "post:publish") },
        expect: "accepted",
      },
      ask(MONDAY + HOUR + 60, { subject: "assistant", permission: "post:publish" }, "allowed", {
        issuedAt: MONDAY + HOUR + 60,
      }),
    ],
  },
  {
    id: "decision/cloud-account-tree",
    title:
      "The owner bans deleting audit logs for every acme member, Tom and next month's joiner included",
    proves: ["D2", "D9"],
    catalog: {
      permissions: [
        "audit-log:read",
        "audit-log:delete",
        "report:read",
        "report:write",
        "access:manage",
      ],
      manager: "access:manage",
      places: { "/": ["org"], "org": ["unit"] },
    },
    statements: [
      allow("owner", "*"),
      allow("deploy-job", "*"),
      allow("tom", "*", ACME),
      allow("ava", "audit-log:delete"),
      allow("noa", "audit-log:delete", "/org=acme/unit=u2"),
      allow("ivo", "access:manage", ACME),
      deny("acme-members", "audit-log:delete", ACME),
      deny("acme-members", "report:write", ACME),
      deny("owner", "report:read", ACME),
      deny("staff", "access:manage"),
    ],
    steps: [
      ask(
        MONDAY,
        {
          subject: "tom",
          groups: ["acme-members"],
          permission: "audit-log:delete",
          place: "/org=acme/unit=u1",
        },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        {
          subject: "tom",
          groups: ["acme-members"],
          permission: "audit-log:read",
          place: "/org=acme/unit=u1",
        },
        "allowed",
      ),
      ask(
        MONDAY,
        { subject: "tom", groups: ["acme-members"], permission: "report:write", place: ACME },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(MONDAY, { subject: "owner", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(
        MONDAY,
        { subject: "deploy-job", groups: ["staff"], permission: "access:manage", place: ACME },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "ivo", groups: ["staff"], permission: "access:manage", place: ACME },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY + 30 * DAY,
        {
          subject: "noa",
          groups: ["acme-members"],
          permission: "audit-log:delete",
          place: "/org=acme/unit=u2",
        },
        "denied",
        { issuedAt: MONDAY + 30 * DAY },
      ),
      ask(
        MONDAY + 30 * DAY,
        { subject: "ava", permission: "audit-log:delete", place: ACME },
        "allowed",
        {
          issuedAt: MONDAY + 30 * DAY,
        },
      ),
    ],
  },
  {
    id: "decision/cluster-bindings",
    title:
      "Groups supplied with each question: a binding in one namespace reaches only it, one on the cluster every namespace",
    proves: ["D1", "D5"],
    catalog: {
      permissions: ["pod:read", "pod:delete", "secret:read"],
      presets: { view: ["pod:read"], admin: ["pod:*", "secret:read"] },
      places: { "/": ["cluster"], "cluster": ["namespace"] },
    },
    statements: [
      assign("team-a", "admin", PAYMENTS),
      assign("team-b", "view", "/cluster=prod"),
      assign("team-c", "admin", "/cluster=prod"),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "vic", groups: ["team-a"], permission: "pod:delete", place: PAYMENTS },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "vic", groups: ["team-a"], permission: "pod:delete", place: SEARCH },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "wen", groups: ["team-b"], permission: "pod:read", place: SEARCH },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "wen", groups: ["team-b"], permission: "pod:read", place: PAYMENTS },
        "allowed",
      ),
      ask(MONDAY, { subject: "ula", permission: "pod:read", place: PAYMENTS }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(
        MONDAY,
        { subject: "ula", groups: ["team-c"], permission: "secret:read", place: SEARCH },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
    ],
  },
];
