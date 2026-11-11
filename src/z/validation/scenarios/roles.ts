import type { CatalogData } from "../../catalog.ts";
import type { Scenario } from "../types.ts";
import { DAY, MONDAY, allow, ask, assign, issue, read, write } from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";
const U1 = "/org=acme/unit=u1";
const TUESDAY = MONDAY + DAY;
const WEDNESDAY = MONDAY + 2 * DAY;

const roles: CatalogData = {
  permissions: [
    "report:read",
    "report:write",
    "billing:read",
    "billing:write",
    "post:read",
    "post:delete",
    "user:ban",
    "deploy:run",
    "access:manage",
  ],
  implies: { "report:write": ["report:read"], "billing:write": ["billing:read"] },
  presets: {
    "support": ["*:read", "-billing:read"],
    "moderator": ["billing:read", "post:delete", "user:ban"],
    "support-billing": ["support", "billing:read"],
    "support-mod": ["support", "moderator"],
    "support-reads": ["support", "*:read"],
    "owner": ["*"],
    "ops": ["deploy:run", "billing:*"],
    "manager": ["owner", "-ops"],
    "no-report-read": ["*", "-report:read"],
    "viewer": ["report:read"],
  },
  places: { "/": ["org"], "org": ["unit"] },
};

export const roleScenarios: readonly Scenario[] = [
  {
    id: "roles/presets-compose",
    title:
      "Support reads everything but billing, composing it gives billing back only when named, a manager is an owner without ops",
    proves: ["D1"],
    catalog: roles,
    statements: [
      assign("ann", "support", ACME),
      assign("bea", "support-billing", ACME),
      assign("cid", "support-mod", ACME),
      assign("fio", "support-reads", ACME),
      assign("dot", "manager", ACME),
      assign("eli", "no-report-read", ACME),
    ],
    steps: (
      [
        ["ann", "report:read", "allowed"],
        ["ann", "billing:read", "denied"],
        ["ann", "post:delete", "denied"],
        ["bea", "billing:read", "allowed"],
        ["bea", "billing:write", "denied"],
        ["cid", "billing:read", "denied"],
        ["cid", "user:ban", "allowed"],
        ["fio", "billing:read", "allowed"],
        ["dot", "report:write", "allowed"],
        ["dot", "deploy:run", "denied"],
        ["dot", "billing:read", "denied"],
        ["eli", "report:read", "denied"],
        ["eli", "report:write", "denied"],
        ["eli", "billing:write", "allowed"],
      ] as const
    ).map(([subject, permission, expect]) =>
      ask(MONDAY, { subject, permission, place: U1 }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "roles/stored-role-homes",
    title:
      "Two organisations define a reviewer of their own, and a stored role composes presets by the same rule",
    proves: ["D1"],
    catalog: roles,
    roles: [
      { name: "reviewer", home: ACME, entries: ["report:read", "post:read"] },
      { name: "reviewer", home: "/org=globex", entries: ["report:write"] },
      { name: "helpdesk", home: ACME, entries: ["support", "billing:read"] },
      { name: "desk-mod", home: ACME, entries: ["support", "moderator"] },
    ],
    statements: [
      assign("gia", "reviewer", U1),
      assign("hub", "reviewer", "/org=globex"),
      assign("ira", "reviewer", "/org=initech"),
      assign("jo", "helpdesk", ACME),
      assign("kat", "desk-mod", ACME),
    ],
    steps: (
      [
        ["gia", "report:read", U1, "allowed"],
        ["gia", "report:write", U1, "denied"],
        ["hub", "report:write", "/org=globex/unit=x", "allowed"],
        ["hub", "post:read", "/org=globex", "denied"],
        ["ira", "report:read", "/org=initech", "denied"],
        ["jo", "billing:read", ACME, "allowed"],
        ["kat", "billing:read", ACME, "denied"],
        ["kat", "user:ban", ACME, "allowed"],
      ] as const
    ).map(([subject, permission, place, expect]) =>
      ask(MONDAY, { subject, permission, place }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "roles/excluding-a-role-reaches-what-implies-it",
    title:
      "A clerk does everything on reports except what an auditor does: writing goes too, since writing a report reads it",
    proves: ["D3", "D8"],
    catalog: roles,
    roles: [
      { name: "auditor", entries: ["report:read"] },
      { name: "clerk", entries: ["report:*", "billing:read", "-auditor"] },
      { name: "scribe", entries: ["report:*", "billing:read"] },
    ],
    statements: [assign("pam", "clerk", ACME), assign("rex", "scribe", ACME)],
    steps: (
      [
        ["pam", "report:read", "denied"],
        ["pam", "report:write", "denied"],
        ["pam", "billing:read", "allowed"],
        ["rex", "report:write", "allowed"],
        ["rex", "report:read", "allowed"],
      ] as const
    ).map(([subject, permission, expect]) =>
      ask(MONDAY, { subject, permission, place: U1 }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "roles/deleted-role-fails-closed",
    title:
      "The auditor role is deleted: every role naming it, directly or through another, gives nothing at all",
    proves: ["D1", "D8"],
    catalog: roles,
    roles: [
      { name: "auditor", entries: ["report:read"] },
      { name: "senior", entries: ["auditor", "report:write"] },
      { name: "lead", entries: ["senior", "post:delete"] },
      { name: "careful", entries: ["report:*", "-auditor"] },
      { name: "plain", entries: ["post:read"] },
    ],
    statements: [
      assign("kai", "senior", ACME),
      assign("lia", "lead", ACME),
      assign("max", "careful", ACME),
      assign("nat", "plain", ACME),
      assign("nat", "auditor", ACME),
    ],
    steps: [
      issue(MONDAY, "kai", "kai"),
      ask(MONDAY, { subject: "kai", permission: "report:write", place: ACME }, "allowed"),
      ask(MONDAY, { subject: "lia", permission: "post:delete", place: ACME }, "allowed"),
      ask(MONDAY, { subject: "max", permission: "report:write", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "nat", permission: "report:read", place: ACME }, "allowed"),
      write({
        roles: [
          { name: "senior", entries: ["auditor", "report:write"] },
          { name: "lead", entries: ["senior", "post:delete"] },
          { name: "careful", entries: ["report:*", "-auditor"] },
          { name: "plain", entries: ["post:read"] },
        ],
      }),
      ask(TUESDAY, { subject: "kai", permission: "report:write", place: ACME }, "denied", {
        issuedAt: TUESDAY,
      }),
      ask(TUESDAY, { subject: "kai", permission: "report:read", place: ACME }, "denied"),
      ask(TUESDAY, { subject: "lia", permission: "post:delete", place: ACME }, "denied", {
        issuedAt: TUESDAY,
      }),
      ask(TUESDAY, { subject: "max", permission: "report:write", place: ACME }, "denied", {
        issuedAt: TUESDAY,
      }),
      ask(TUESDAY, { subject: "nat", permission: "post:read", place: ACME }, "allowed", {
        issuedAt: TUESDAY,
      }),
      ask(TUESDAY, { subject: "nat", permission: "report:read", place: ACME }, "denied", {
        issuedAt: TUESDAY,
      }),
      read(TUESDAY, "kai", { permission: "report:write", place: ACME }, "allowed"),
    ],
  },
  {
    id: "roles/preset-wins-over-stored",
    title:
      "A stored role named like a preset reads as the preset, also when another stored role references it",
    proves: ["D1"],
    catalog: roles,
    roles: [
      { name: "viewer", entries: ["report:write"] },
      { name: "viewer-plus", entries: ["viewer", "post:read"] },
    ],
    statements: [assign("oli", "viewer", ACME), assign("pam", "viewer-plus", ACME)],
    steps: (
      [
        ["oli", "report:read", "allowed"],
        ["oli", "report:write", "denied"],
        ["pam", "report:read", "allowed"],
        ["pam", "post:read", "allowed"],
        ["pam", "report:write", "denied"],
      ] as const
    ).map(([subject, permission, expect]) =>
      ask(MONDAY, { subject, permission, place: ACME }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "roles/unknown-names-in-stored-roles",
    title:
      "A dropped permission in a stored role is ignored, a missing role in one empties it, an unknown assignment gives nothing",
    proves: ["D1", "D5"],
    catalog: roles,
    roles: [
      {
        name: "legacy-editor",
        entries: ["report:write", "legacy:export", "-legacy:import", "invoice:*"],
      },
      { name: "ghost-ref", entries: ["report:read", "retired"] },
      { name: "ghost-ex", entries: ["post:read", "-retired"] },
    ],
    statements: [
      assign("pia", "legacy-editor", ACME),
      assign("quin", "ghost-ref", ACME),
      assign("rory", "ghost-ex", ACME),
      assign("ray", "intern", ACME),
      allow("ray", "post:read", ACME),
    ],
    steps: (
      [
        ["pia", "report:write", "allowed"],
        ["pia", "report:read", "allowed"],
        ["quin", "report:read", "denied"],
        ["rory", "post:read", "denied"],
        ["ray", "post:read", "allowed"],
        ["ray", "report:read", "denied"],
      ] as const
    ).map(([subject, permission, expect]) =>
      ask(MONDAY, { subject, permission, place: ACME }, expect, { issuedAt: MONDAY }),
    ),
  },
  {
    id: "roles/edited-after-issue",
    title:
      "A stored role is edited, then deleted: the statements answer at once, grants issued before keep what it was",
    proves: ["D8"],
    catalog: roles,
    roles: [{ name: "reviewer", home: ACME, entries: ["report:read", "post:delete"] }],
    statements: [assign("ian", "reviewer", U1)],
    steps: [
      issue(MONDAY, "ian", "ian"),
      write({ roles: [{ name: "reviewer", home: ACME, entries: ["report:read"] }] }),
      read(TUESDAY, "ian", { permission: "post:delete", place: U1 }, "allowed"),
      ask(TUESDAY, { subject: "ian", permission: "post:delete", place: U1 }, "denied", {
        issuedAt: TUESDAY,
      }),
      ask(TUESDAY, { subject: "ian", permission: "report:read", place: U1 }, "allowed"),
      write({ roles: [] }),
      ask(WEDNESDAY, { subject: "ian", permission: "report:read", place: U1 }, "denied", {
        issuedAt: WEDNESDAY,
      }),
      read(WEDNESDAY, "ian", { permission: "report:read", place: U1 }, "allowed"),
    ],
  },
];
