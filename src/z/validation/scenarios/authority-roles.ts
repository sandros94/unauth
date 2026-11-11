import type { Scenario } from "../types.ts";
import {
  ACME,
  CLOUD,
  FRIDAY,
  GLOBEX,
  HOUR,
  MINUTE,
  MONDAY,
  P1,
  allow,
  ask,
  assign,
  define,
  genesis,
  place,
  remove,
} from "./_internal/authority.ts";

export const authorityRoleScenarios: readonly Scenario[] = [
  {
    id: "authority/roles/defined-at-a-home",
    title: "An organisation defines its own roles, used inside it and nowhere else",
    proves: ["A6", "A1", "A2"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("bo", "access:manage", { place: ACME }),
      ),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("bo", "report:read", { place: ACME })),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "analyst", home: ACME, entries: ["report:write", "vm:start"] },
      ),
      define(
        { at: MONDAY + HOUR, author: "bo" },
        { name: "reader", home: ACME, entries: ["report:read"] },
      ),
      define(
        { at: MONDAY + HOUR, author: "bo" },
        { name: "runner", home: ACME, entries: ["vm:start"] },
        ["not-held"],
      ),
      define(
        { at: MONDAY + HOUR, author: "bo" },
        { name: "reader", home: GLOBEX, entries: ["report:read"] },
        ["not-manager", "not-held"],
      ),
      place({ at: MONDAY + 2 * HOUR, author: "ola" }, assign("ike", "analyst", { place: P1 })),
      place({ at: MONDAY + 2 * HOUR, author: "ola" }, assign("ivy", "analyst", { place: ACME })),
      place(
        { at: MONDAY + 2 * HOUR, author: "owner" },
        assign("ike", "analyst", { place: GLOBEX }),
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      place(
        { at: MONDAY + 2 * HOUR, author: "owner" },
        assign("ike", "analyst"),
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      ask({ at: MONDAY + 3 * HOUR, subject: "ike", place: P1 }, "vm:start", "allowed"),
      ask({ at: MONDAY + 3 * HOUR, subject: "ike", place: GLOBEX }, "vm:start", "denied"),
      define(
        { at: MONDAY + 4 * HOUR, author: "bo" },
        { name: "reader", home: ACME, entries: ["report:read", "vm:start"] },
        ["not-held"],
      ),
      define(
        { at: MONDAY + 4 * HOUR, author: "ola" },
        { name: "analyst", home: ACME, entries: ["report:write"] },
      ),
      ask({ at: MONDAY + 5 * HOUR, subject: "ike", place: P1 }, "vm:start", "denied"),
      ask({ at: MONDAY + 5 * HOUR, subject: "ike", place: P1 }, "report:read", "allowed"),
    ],
  },
  {
    id: "authority/roles/one-meaning-per-name",
    title: "A role name means one thing along every chain, while sibling organisations reuse it",
    proves: ["A6"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "viewer", home: ACME, entries: ["report:read"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "analyst", home: ACME, entries: ["report:read"] },
      ),
      define(
        { at: MONDAY + 2 * HOUR, author: "owner" },
        { name: "analyst", entries: ["report:read"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + 2 * HOUR, author: "ola" },
        { name: "analyst", home: P1, entries: ["report:read"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + 2 * HOUR, author: "owner" },
        { name: "analyst", home: GLOBEX, entries: ["report:write"] },
      ),
      place(
        { at: MONDAY + 3 * HOUR, author: "owner" },
        assign("gus", "analyst", { place: GLOBEX }),
      ),
      place({ at: MONDAY + 3 * HOUR, author: "ola" }, assign("ike", "analyst", { place: ACME })),
      ask({ at: MONDAY + 4 * HOUR, subject: "gus", place: GLOBEX }, "report:write", "allowed"),
      ask({ at: MONDAY + 4 * HOUR, subject: "ike", place: ACME }, "report:write", "denied"),
      ask({ at: MONDAY + 4 * HOUR, subject: "ike", place: ACME }, "report:read", "allowed"),
    ],
  },
  {
    id: "authority/roles/references-point-up",
    title: "A project role builds on organisation roles, never the other way round",
    proves: ["A6"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "p1-dev", home: P1, entries: ["report:write"] },
      ),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "acme-dev", home: ACME, entries: ["p1-dev"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "acme-limited", home: ACME, entries: ["*", "-p1-dev"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "acme-ghost", home: ACME, entries: ["ghost"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "acme-base", home: ACME, entries: ["vm:start"] },
      ),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "p1-lead", home: P1, entries: ["acme-base", "p1-dev", "support"] },
      ),
      place({ at: MONDAY + 2 * HOUR, author: "ola" }, assign("ike", "p1-lead", { place: P1 })),
      ask({ at: MONDAY + 3 * HOUR, subject: "ike", place: P1 }, "vm:start", "allowed"),
      ask({ at: MONDAY + 3 * HOUR, subject: "ike", place: P1 }, "report:write", "allowed"),
    ],
  },
  {
    id: "authority/roles/no-cycles",
    title:
      "Two roles that would contain each other, through a reference or an exclusion, are refused",
    proves: ["A6"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "triage", home: ACME, entries: ["report:read"] },
      ),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "oncall", home: ACME, entries: ["triage", "vm:start"] },
      ),
      define(
        { at: MONDAY + 2 * HOUR, author: "ola" },
        { name: "triage", home: ACME, entries: ["oncall"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + 2 * HOUR, author: "ola" },
        { name: "triage", home: ACME, entries: ["report:read", "-oncall"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      define(
        { at: MONDAY + 2 * HOUR, author: "ola" },
        { name: "loop", home: ACME, entries: ["loop"] },
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      place({ at: MONDAY + 3 * HOUR, author: "ola" }, assign("ike", "oncall", { place: ACME })),
      ask({ at: MONDAY + 4 * HOUR, subject: "ike", place: ACME }, "report:read", "allowed"),
    ],
  },
  {
    id: "authority/roles/an-edit-gives-nothing-the-author-lacks",
    title:
      "A manager who reads reports cannot widen a shared role through permissions, presets or wildcards",
    proves: ["G1", "A2", "A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("bo", "access:manage", { place: ACME }),
      ),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("bo", "report:read", { place: ACME })),
      define(
        { at: MONDAY + HOUR, author: "ola" },
        { name: "helper", home: ACME, entries: ["report:read"] },
      ),
      place({ at: MONDAY + 2 * HOUR, author: "bo" }, assign("ike", "helper", { place: ACME })),
      define(
        { at: MONDAY + 3 * HOUR, author: "bo" },
        { name: "helper", home: ACME, entries: ["report:read", "report:write"] },
        ["not-held"],
      ),
      define(
        { at: MONDAY + 3 * HOUR, author: "bo" },
        { name: "helper", home: ACME, entries: ["editor"] },
        ["not-held"],
      ),
      define(
        { at: MONDAY + 3 * HOUR, author: "bo" },
        { name: "helper", home: ACME, entries: ["*:read"] },
        ["not-held"],
      ),
      define(
        { at: MONDAY + 3 * HOUR, author: "bo" },
        { name: "helper", home: ACME, entries: ["support"] },
      ),
      ask({ at: MONDAY + 4 * HOUR, subject: "ike", place: ACME }, "audit-log:read", "denied"),
      define(
        { at: MONDAY + 5 * HOUR, author: "ola" },
        { name: "helper", home: ACME, entries: ["support", "vm:start"] },
      ),
      ask({ at: MONDAY + 6 * HOUR, subject: "ike", place: ACME }, "vm:start", "allowed"),
      remove({ at: MONDAY + 6 * HOUR, author: "bo" }, assign("ike", "helper", { place: ACME }), [
        "not-held",
      ]),
      remove({ at: MONDAY + 7 * HOUR, author: "ola" }, assign("ike", "helper", { place: ACME })),
      ask({ at: MONDAY + 8 * HOUR, subject: "ike", place: ACME }, "vm:start", "denied"),
    ],
  },
  {
    id: "authority/roles/a-definition-needs-a-holding-with-no-end",
    title: "A manager whose writing ends on Friday cannot put writing into a role that lasts",
    proves: ["A2", "A6"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("cal", "access:manage", { place: ACME }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("cal", "report:write", { place: ACME, until: FRIDAY }),
      ),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("cal", "vm:start", { place: ACME })),
      define(
        { at: MONDAY + HOUR, author: "cal" },
        { name: "writer", home: ACME, entries: ["report:write"] },
        ["not-held"],
      ),
      define(
        { at: MONDAY + HOUR, author: "cal" },
        { name: "runner", home: ACME, entries: ["vm:start"] },
      ),
      place({ at: MONDAY + 2 * HOUR, author: "cal" }, assign("ike", "runner", { place: P1 })),
      define(
        { at: MONDAY + 3 * HOUR, author: "cal" },
        { name: "runner", home: ACME, entries: ["vm:start", "report:read"] },
        ["not-held"],
      ),
      place(
        { at: MONDAY + 4 * HOUR, author: "owner" },
        allow("cal", "report:read", { place: ACME }),
      ),
      define(
        { at: MONDAY + 5 * HOUR, author: "cal" },
        { name: "runner", home: ACME, entries: ["vm:start", "report:read"] },
      ),
      ask({ at: FRIDAY + HOUR, subject: "ike", place: P1 }, "report:read", "allowed"),
    ],
  },
];
