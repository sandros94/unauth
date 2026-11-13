import type { CatalogData } from "../../catalog.ts";
import type { Scenario } from "../types.ts";
import {
  DAY,
  MONDAY,
  allow,
  ask,
  assign,
  deny,
  deploy,
  diverged,
  issue,
  read,
  write,
} from "./_internal/steps.ts";

const ACME = "/org=acme";
const U7 = "/org=acme/unit=u7";

const TUESDAY = MONDAY + DAY;
const WEDNESDAY = MONDAY + 2 * DAY;

const PERMISSIONS = diverged(["permissions"]);
const PRESETS = diverged(["presets"]);

const orgs = { "/": ["org"], "org": ["unit"] };

const reports: CatalogData = {
  permissions: ["report:read", "report:write"],
  places: orgs,
};

const presets: CatalogData = {
  permissions: ["post:read", "report:read", "report:write"],
  presets: { viewer: ["report:read"], editor: ["viewer", "report:write"] },
  places: orgs,
};

const ada: CatalogData = {
  permissions: ["billing:read", "post:read", "report:read", "report:write"],
  presets: { viewer: ["*:read"] },
  places: orgs,
};

/**
 * Grants issued under one catalog and read under another (G8 of the model): what the permissions,
 * implications and structure in force make of what the grants carry, and how presets read as
 * copies, kept as they were, or by name, read from the catalog in force. No read is refused because
 * the catalog changed.
 */
export const catalogScenarios: readonly Scenario[] = [
  {
    id: "grants/new-permission-under-held-pattern",
    title:
      "Kim holds every report permission at the organisation: exporting is added to the catalog, and her grants give it without being issued again",
    proves: ["G8"],
    catalog: reports,
    statements: [allow("kim", "report:*", ACME)],
    steps: [
      issue(MONDAY, "kim", "kim"),
      read(MONDAY, "kim", { permission: "report:write", place: ACME }, "allowed", null),
      deploy({ ...reports, permissions: ["report:export", "report:read", "report:write"] }),
      read(TUESDAY, "kim", { permission: "report:export", place: ACME }, "allowed", PERMISSIONS),
      ask(TUESDAY, { subject: "kim", permission: "report:export", place: ACME }, "allowed"),
    ],
  },
  {
    id: "grants/removed-permission-is-inert",
    title:
      "Writing reports and reading billing leave the catalog: Lou's allows of them give nothing, writing no longer brings reading, and the read names both",
    proves: ["G8"],
    catalog: {
      permissions: ["billing:read", "post:read", "report:read", "report:write"],
      implies: { "report:write": ["report:read"] },
      places: orgs,
    },
    statements: [allow("lou", "report:write", ACME), allow("lou", "billing:read", ACME)],
    steps: [
      issue(MONDAY, "lou", "lou"),
      read(MONDAY, "lou", { permission: "report:read", place: ACME }, "allowed", null),
      deploy({ permissions: ["post:read", "report:read"], places: orgs }),
      read(
        TUESDAY,
        "lou",
        { permission: "report:read", place: ACME },
        "denied",
        diverged(["permissions"], { permissions: ["billing:read", "report:write"] }),
      ),
      read(
        TUESDAY,
        "lou",
        { permission: "report:write", place: ACME },
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
      ),
      ask(TUESDAY, { subject: "lou", permission: "report:read", place: ACME }, "denied"),
      issue(TUESDAY, "after", "lou"),
      read(TUESDAY, "after", { permission: "report:read", place: ACME }, "denied", null),
    ],
  },
  {
    id: "grants/deny-blocks-again-when-redeclared",
    title:
      "Mo is denied exporting reports: exporting leaves the catalog and comes back, and the deny blocks again, in grants issued before and during the gap",
    proves: ["G8", "G2"],
    catalog: { permissions: ["report:export", "report:read"], places: orgs },
    statements: [allow("mo", "report:*", ACME), deny("mo", "report:export", ACME)],
    steps: [
      issue(MONDAY, "before", "mo"),
      read(MONDAY, "before", { permission: "report:export", place: ACME }, "denied"),
      deploy({ permissions: ["report:read"], places: orgs }),
      read(
        TUESDAY,
        "before",
        { permission: "report:read", place: ACME },
        "allowed",
        diverged(["permissions"], { permissions: ["report:export"] }),
      ),
      read(
        TUESDAY,
        "before",
        { permission: "report:export", place: ACME },
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
      ),
      issue(TUESDAY, "during", "mo"),
      deploy({ permissions: ["report:export", "report:read"], places: orgs }),
      read(WEDNESDAY, "before", { permission: "report:export", place: ACME }, "denied", null),
      read(WEDNESDAY, "before", { permission: "report:read", place: ACME }, "allowed"),
      read(
        WEDNESDAY,
        "during",
        { permission: "report:export", place: ACME },
        "denied",
        PERMISSIONS,
      ),
      ask(WEDNESDAY, { subject: "mo", permission: "report:export", place: ACME }, "denied"),
    ],
  },
  {
    id: "grants/implication-added",
    title:
      "Writing a report comes to imply reading it: Ned, who may write, now reads, and Pat, denied reading, can no longer write",
    proves: ["G8", "G3"],
    catalog: { permissions: ["report:read", "report:write"], places: orgs },
    statements: [
      allow("ned", "report:write", ACME),
      allow("pat", "report:*", ACME),
      deny("pat", "report:read", ACME),
    ],
    steps: [
      issue(MONDAY, "ned", "ned"),
      issue(MONDAY, "pat", "pat"),
      read(MONDAY, "ned", { permission: "report:read", place: ACME }, "denied"),
      read(MONDAY, "pat", { permission: "report:write", place: ACME }, "allowed"),
      deploy({ ...reports, implies: { "report:write": ["report:read"] } }),
      read(TUESDAY, "ned", { permission: "report:read", place: ACME }, "allowed", PERMISSIONS),
      read(TUESDAY, "pat", { permission: "report:write", place: ACME }, "denied", PERMISSIONS),
      ask(TUESDAY, { subject: "ned", permission: "report:read", place: ACME }, "allowed"),
      ask(TUESDAY, { subject: "pat", permission: "report:write", place: ACME }, "denied"),
    ],
  },
  {
    id: "grants/implication-removed",
    title:
      "Writing a report stops implying reading it: Ned, who may only write, no longer reads, from grants issued before",
    proves: ["G8"],
    catalog: { ...reports, implies: { "report:write": ["report:read"] } },
    statements: [allow("ned", "report:write", ACME)],
    steps: [
      issue(MONDAY, "ned", "ned"),
      read(MONDAY, "ned", { permission: "report:read", place: ACME }, "allowed"),
      deploy(reports),
      read(TUESDAY, "ned", { permission: "report:read", place: ACME }, "denied", PERMISSIONS),
      read(TUESDAY, "ned", { permission: "report:write", place: ACME }, "allowed"),
    ],
  },
  {
    id: "grants/place-stops-fitting-and-fits-again",
    title:
      "Units are dropped from the structure and restored: Oz's grants are read meanwhile, a unit cannot be asked about, and her unit reads again once it fits",
    proves: ["G8"],
    catalog: { permissions: ["report:read"], places: orgs },
    statements: [allow("oz", "report:read", U7), allow("oz", "report:read", "/org=globex")],
    steps: [
      issue(MONDAY, "before", "oz"),
      read(MONDAY, "before", { permission: "report:read", place: U7 }, "allowed"),
      deploy({ permissions: ["report:read"], places: { "/": ["org"] } }),
      read(
        TUESDAY,
        "before",
        { permission: "report:read", place: "/org=globex" },
        "allowed",
        PERMISSIONS,
      ),
      read(TUESDAY, "before", { permission: "report:read", place: ACME }, "denied"),
      read(TUESDAY, "before", { permission: "report:read", place: U7 }, "ERR_AUTHZ_PLACE_OUTSIDE"),
      ask(
        TUESDAY,
        { subject: "oz", permission: "report:read", place: U7 },
        "ERR_AUTHZ_PLACE_OUTSIDE",
      ),
      issue(TUESDAY, "during", "oz"),
      deploy({ permissions: ["report:read"], places: orgs }),
      read(WEDNESDAY, "before", { permission: "report:read", place: U7 }, "allowed", null),
      read(WEDNESDAY, "during", { permission: "report:read", place: U7 }, "allowed", PERMISSIONS),
    ],
  },
  {
    id: "grants/preset-changed",
    title:
      "The viewer preset moves from reports to posts: Ada's copies keep reports and say the copy diverged, her grants by name follow the catalog as the statements do",
    proves: ["G8"],
    catalog: presets,
    statements: [assign("ada", "viewer", ACME)],
    steps: [
      issue(MONDAY, "copies", "ada", { presets: "copies" }),
      issue(MONDAY, "names", "ada", { presets: "names" }),
      read(MONDAY, ["copies", "names"], { permission: "report:read", place: ACME }, "allowed"),
      deploy({
        ...presets,
        presets: { viewer: ["post:read"], editor: ["viewer", "report:write"] },
      }),
      read(
        TUESDAY,
        "copies",
        { permission: "report:read", place: ACME },
        "allowed",
        diverged(["presets"], { presets: ["viewer"] }),
      ),
      read(TUESDAY, "copies", { permission: "post:read", place: ACME }, "denied"),
      read(TUESDAY, "names", { permission: "report:read", place: ACME }, "denied", PRESETS),
      read(TUESDAY, "names", { permission: "post:read", place: ACME }, "allowed", PRESETS),
      read(
        TUESDAY,
        ["copies", "names"],
        { permission: "report:read", place: ACME },
        "denied",
        diverged(["presets"], { presets: ["viewer"] }),
      ),
      ask(TUESDAY, { subject: "ada", permission: "report:read", place: ACME }, "denied", {
        issuedAt: TUESDAY,
      }),
      ask(TUESDAY, { subject: "ada", permission: "post:read", place: ACME }, "allowed", {
        issuedAt: TUESDAY,
      }),
    ],
  },
  {
    id: "grants/preset-removed",
    title:
      "The viewer preset is removed from the catalog: Ada's copy still reads reports and is reported diverged, by name viewer is a role that no longer exists",
    proves: ["G8"],
    catalog: presets,
    statements: [assign("ada", "viewer", ACME)],
    steps: [
      issue(MONDAY, "copies", "ada", { presets: "copies" }),
      issue(MONDAY, "names", "ada", { presets: "names" }),
      deploy({ ...presets, presets: { editor: ["report:read", "report:write"] } }),
      read(
        TUESDAY,
        "copies",
        { permission: "report:read", place: ACME },
        "allowed",
        diverged(["presets"], { presets: ["viewer"] }),
      ),
      read(TUESDAY, "names", { permission: "report:read", place: ACME }, "denied", PRESETS),
      ask(TUESDAY, { subject: "ada", permission: "report:read", place: ACME }, "denied", {
        issuedAt: TUESDAY,
      }),
    ],
  },
  {
    id: "grants/preset-not-held-changed",
    title:
      "Only the editor preset changes and Bo holds viewer: her copies and her grants by name read on, and name no diverged role",
    proves: ["G8"],
    catalog: presets,
    statements: [assign("bo", "viewer", ACME)],
    steps: [
      issue(MONDAY, "copies", "bo", { presets: "copies" }),
      issue(MONDAY, "names", "bo", { presets: "names" }),
      deploy({ ...presets, presets: { viewer: ["report:read"], editor: ["report:write"] } }),
      read(TUESDAY, "copies", { permission: "report:read", place: ACME }, "allowed", PRESETS),
      read(TUESDAY, "names", { permission: "report:read", place: ACME }, "allowed", PRESETS),
      read(TUESDAY, "names", { permission: "post:read", place: ACME }, "denied", PRESETS),
    ],
  },
  {
    id: "grants/permissions-changed-presets-same",
    title:
      "Billing is added and presets stay: Cy's viewer of everything readable reads billing, whether her grants carry it as a copy or by name",
    proves: ["G8"],
    catalog: { ...ada, permissions: ["post:read", "report:read", "report:write"] },
    statements: [assign("cy", "viewer", ACME)],
    steps: [
      issue(MONDAY, "cy", "cy"),
      read(MONDAY, "cy", { permission: "report:read", place: ACME }, "allowed", null),
      deploy(ada),
      read(TUESDAY, "cy", { permission: "billing:read", place: ACME }, "allowed", PERMISSIONS),
      read(TUESDAY, "cy", { permission: "report:write", place: ACME }, "denied"),
    ],
  },
  {
    id: "grants/presets-changed-none-named",
    title:
      "Presets change and Dee's grants name none: they are read whichever way presets would travel",
    proves: ["G8"],
    catalog: presets,
    statements: [allow("dee", "report:read", ACME)],
    steps: [
      issue(MONDAY, "dee", "dee"),
      deploy({ ...presets, presets: { viewer: ["post:read"] } }),
      read(TUESDAY, "dee", { permission: "report:read", place: ACME }, "allowed", PRESETS),
      read(TUESDAY, "dee", { permission: "post:read", place: ACME }, "denied"),
    ],
  },
  {
    id: "grants/stored-role-references-preset",
    title:
      "Ada's stored reviewer builds on viewer, which moves from everything readable to posts: the copy keeps reports and is reported, by name she reads posts and no longer reports",
    proves: ["G8", "G4"],
    catalog: ada,
    roles: [{ name: "reviewer", entries: ["viewer", "report:write", "-billing:read"] }],
    statements: [assign("ada", "reviewer", ACME), allow("ada", "billing:read", U7)],
    steps: [
      issue(MONDAY, "copies", "ada", { presets: "copies" }),
      issue(MONDAY, "names", "ada", { presets: "names" }),
      read(MONDAY, ["copies", "names"], { permission: "billing:read", place: ACME }, "denied"),
      deploy({ ...ada, presets: { viewer: ["post:read"] } }),
      read(
        TUESDAY,
        "copies",
        { permission: "report:read", place: ACME },
        "allowed",
        diverged(["presets"], { presets: ["viewer"] }),
      ),
      read(TUESDAY, "copies", { permission: "billing:read", place: ACME }, "denied"),
      read(TUESDAY, "copies", { permission: "billing:read", place: U7 }, "allowed"),
      read(TUESDAY, "copies", { permission: "report:write", place: ACME }, "allowed"),
      read(TUESDAY, "names", { permission: "report:write", place: ACME }, "allowed", PRESETS),
      read(TUESDAY, "names", { permission: "report:read", place: ACME }, "denied", PRESETS),
      read(TUESDAY, "names", { permission: "post:read", place: ACME }, "allowed"),
      read(TUESDAY, "names", { permission: "billing:read", place: ACME }, "denied"),
      ask(TUESDAY, { subject: "ada", permission: "report:read", place: ACME }, "denied"),
      ask(TUESDAY, { subject: "ada", permission: "post:read", place: ACME }, "allowed"),
    ],
  },
  {
    id: "grants/stored-role-alone-presets-changed",
    title:
      "Eve holds a stored analyst role that names no preset: presets change, and her grants are read whichever way presets travel",
    proves: ["G8"],
    catalog: presets,
    roles: [{ name: "analyst", entries: ["report:read", "report:write"] }],
    statements: [assign("eve", "analyst", ACME)],
    steps: [
      issue(MONDAY, "eve", "eve"),
      deploy({ ...presets, presets: { viewer: ["post:read"] } }),
      read(TUESDAY, "eve", { permission: "report:write", place: ACME }, "allowed", PRESETS),
      read(TUESDAY, "eve", { permission: "post:read", place: ACME }, "denied"),
    ],
  },
  {
    id: "grants/stored-role-named-like-preset-not-carried",
    title:
      "Fay's stored role shares the name of the viewer preset, which is later removed: her grants carried the preset, never the stored role, so by name viewer no longer exists for them",
    proves: ["G8", "G9"],
    catalog: { ...presets, presets: { viewer: ["report:read"] } },
    roles: [{ name: "viewer", entries: ["report:write"] }],
    statements: [assign("fay", "viewer", ACME)],
    steps: [
      issue(MONDAY, "copies", "fay", { presets: "copies" }),
      issue(MONDAY, "names", "fay", { presets: "names" }),
      read(MONDAY, ["copies", "names"], { permission: "report:read", place: ACME }, "allowed"),
      read(MONDAY, ["copies", "names"], { permission: "report:write", place: ACME }, "denied"),
      deploy({ permissions: presets.permissions, places: orgs }),
      read(
        TUESDAY,
        "copies",
        { permission: "report:read", place: ACME },
        "allowed",
        diverged(["presets"], { presets: ["viewer"] }),
      ),
      read(TUESDAY, "copies", { permission: "report:write", place: ACME }, "denied"),
      read(TUESDAY, "names", { permission: "report:write", place: ACME }, "denied", PRESETS),
      read(TUESDAY, "names", { permission: "report:read", place: ACME }, "denied", PRESETS),
      ask(TUESDAY, { subject: "fay", permission: "report:write", place: ACME }, "allowed"),
    ],
  },
  {
    id: "grants/sets-tell-together",
    title:
      "A cookie issued before a preset change and a session issued before a permission was dropped are read together: what diverged is told of both",
    proves: ["G8"],
    catalog: {
      permissions: ["post:read", "report:read"],
      presets: { viewer: ["report:read"] },
      places: orgs,
    },
    statements: [assign("gus", "viewer", ACME), allow("gus", "post:read", ACME)],
    steps: [
      issue(MONDAY, "cookie", "gus", { presets: "copies" }),
      write({ save: [allow("gus", "legacy:export", ACME)] }),
      deploy({
        permissions: ["legacy:export", "post:read", "report:read"],
        presets: { viewer: ["post:read"] },
        places: orgs,
      }),
      issue(TUESDAY, "session", "gus", { presets: "copies" }),
      deploy({
        permissions: ["post:read", "report:read"],
        presets: { viewer: ["post:read"] },
        places: orgs,
      }),
      read(
        WEDNESDAY,
        "cookie",
        { permission: "post:read", place: ACME },
        "allowed",
        diverged(["presets"], { presets: ["viewer"] }),
      ),
      read(
        WEDNESDAY,
        "session",
        { permission: "post:read", place: ACME },
        "allowed",
        diverged(["permissions"], { permissions: ["legacy:export"] }),
      ),
      read(
        WEDNESDAY,
        ["cookie", "session"],
        { permission: "post:read", place: ACME },
        "allowed",
        diverged(["permissions", "presets"], {
          permissions: ["legacy:export"],
          presets: ["viewer"],
        }),
      ),
      read(WEDNESDAY, ["cookie", "session"], { permission: "report:read", place: ACME }, "denied"),
      write({ remove: [{ kind: "allow", subject: "gus", value: "legacy:export", place: ACME }] }),
      issue(WEDNESDAY, "fresh-cookie", "gus"),
      issue(WEDNESDAY, "fresh-session", "gus"),
      read(
        WEDNESDAY,
        ["fresh-cookie", "fresh-session"],
        { permission: "post:read", place: ACME },
        "allowed",
        null,
      ),
    ],
  },
  {
    id: "grants/unresolvable-roles-left-out",
    title:
      "Stored roles built on a deleted role, excluding one, or caught in a cycle are left out at issue: the allows beside them answer, and with no preset named the grants are read under other presets",
    proves: ["G9", "G8"],
    catalog: presets,
    roles: [
      { name: "broken", entries: ["ghost"] },
      { name: "lead", entries: ["broken", "report:write"] },
      { name: "careful", entries: ["report:*", "-ghost"] },
      { name: "triage", entries: ["oncall", "report:read"] },
      { name: "oncall", entries: ["triage", "report:write"] },
    ],
    statements: [
      ...(["hal", "ida", "jon", "kit"] as const).map((subject) =>
        allow(subject, "post:read", ACME),
      ),
      assign("hal", "broken", ACME),
      assign("ida", "lead", ACME),
      assign("jon", "careful", ACME),
      assign("kit", "triage", ACME),
    ],
    steps: [
      ...(["hal", "ida", "jon", "kit"] as const).flatMap((subject) => [
        issue(MONDAY, subject, subject),
        read(MONDAY, subject, { permission: "post:read", place: ACME }, "allowed", null),
        read(MONDAY, subject, { permission: "report:read", place: ACME }, "denied"),
        read(MONDAY, subject, { permission: "report:write", place: ACME }, "denied"),
      ]),
      deploy({ ...presets, presets: { viewer: ["post:read"] } }),
      ...(["hal", "ida", "jon", "kit"] as const).flatMap((subject) => [
        read(TUESDAY, subject, { permission: "post:read", place: ACME }, "allowed", PRESETS),
        read(TUESDAY, subject, { permission: "report:write", place: ACME }, "denied"),
        ask(TUESDAY, { subject, permission: "report:write", place: ACME }, "denied"),
      ]),
    ],
  },
  {
    id: "grants/roles-giving-nothing-kept",
    title:
      "Kai holds a stored role with no entries and one whose pattern matches nothing yet: both are kept, and once invoices are declared his grants give them",
    proves: ["G8"],
    catalog: { permissions: ["report:read"], places: orgs },
    roles: [
      { name: "empty", entries: [] },
      { name: "invoices", entries: ["invoice:*"] },
    ],
    statements: [assign("kai", "empty", ACME), assign("kai", "invoices", ACME)],
    steps: [
      issue(MONDAY, "kai", "kai"),
      read(MONDAY, "kai", { permission: "report:read", place: ACME }, "denied", null),
      deploy({ permissions: ["invoice:pay", "report:read"], places: orgs }),
      read(TUESDAY, "kai", { permission: "invoice:pay", place: ACME }, "allowed", PERMISSIONS),
      read(TUESDAY, "kai", { permission: "report:read", place: ACME }, "denied"),
      ask(TUESDAY, { subject: "kai", permission: "invoice:pay", place: ACME }, "allowed"),
    ],
  },
  {
    id: "grants/stored-role-then-preset-of-its-name",
    title:
      "Grants hold Rae's stored reviewer, then a catalog declares a preset of that name with other entries: the grants answer with the stored role as held and tell it diverged, the statements answer with the preset",
    proves: ["G8"],
    catalog: { permissions: ["report:read", "report:write"], places: orgs },
    roles: [{ name: "reviewer", entries: ["report:write"] }],
    statements: [assign("rae", "reviewer", ACME)],
    steps: [
      issue(MONDAY, "rae", "rae"),
      read(MONDAY, "rae", { permission: "report:write", place: ACME }, "allowed", null),
      deploy({
        permissions: ["report:read", "report:write"],
        presets: { reviewer: ["report:read"] },
        places: orgs,
      }),
      read(
        TUESDAY,
        "rae",
        { permission: "report:write", place: ACME },
        "allowed",
        diverged(["presets"], { presets: ["reviewer"] }),
      ),
      read(TUESDAY, "rae", { permission: "report:read", place: ACME }, "denied"),
      ask(TUESDAY, { subject: "rae", permission: "report:write", place: ACME }, "denied", {
        issuedAt: TUESDAY,
      }),
      ask(TUESDAY, { subject: "rae", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: TUESDAY,
      }),
    ],
  },
  {
    id: "grants/referenced-stored-role-then-preset-of-its-name",
    title:
      "Sal's stored lead builds on a stored helper, then a catalog gives helper's name to a preset with other entries: helper is read as held and told diverged",
    proves: ["G8"],
    catalog: presets,
    roles: [
      { name: "helper", entries: ["report:read"] },
      { name: "lead", entries: ["helper", "report:write"] },
    ],
    statements: [assign("sal", "lead", ACME)],
    steps: [
      issue(MONDAY, "sal", "sal"),
      deploy({ ...presets, presets: { ...presets.presets, helper: ["post:read"] } }),
      read(
        TUESDAY,
        "sal",
        { permission: "report:read", place: ACME },
        "allowed",
        diverged(["presets"], { presets: ["helper"] }),
      ),
      read(TUESDAY, "sal", { permission: "post:read", place: ACME }, "denied"),
      ask(TUESDAY, { subject: "sal", permission: "post:read", place: ACME }, "allowed"),
    ],
  },
  {
    id: "grants/stored-role-then-same-preset",
    title:
      "A catalog declares a preset named like Tia's stored auditor, with the same entries: the presets segment is told, no role has diverged",
    proves: ["G8"],
    catalog: presets,
    roles: [{ name: "auditor", entries: ["report:read"] }],
    statements: [assign("tia", "auditor", ACME)],
    steps: [
      issue(MONDAY, "tia", "tia"),
      deploy({ ...presets, presets: { ...presets.presets, auditor: ["report:read"] } }),
      read(TUESDAY, "tia", { permission: "report:read", place: ACME }, "allowed", PRESETS),
    ],
  },
  {
    id: "grants/presets-changed-none-held",
    title:
      "Uma holds a copy of viewer and a stored analyst, and the catalog changes only editor: the presets segment is told, no role has diverged",
    proves: ["G8"],
    catalog: presets,
    roles: [{ name: "analyst", entries: ["report:write"] }],
    statements: [assign("uma", "viewer", ACME), assign("uma", "analyst", ACME)],
    steps: [
      issue(MONDAY, "uma", "uma", { presets: "copies" }),
      deploy({ ...presets, presets: { viewer: ["report:read"], editor: ["post:read"] } }),
      read(TUESDAY, "uma", { permission: "report:read", place: ACME }, "allowed", PRESETS),
      read(TUESDAY, "uma", { permission: "report:write", place: ACME }, "allowed"),
    ],
  },
];
