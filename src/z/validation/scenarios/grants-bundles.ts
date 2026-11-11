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
  issue,
  read,
  write,
} from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";
const D1 = "/drive=d1";
const CONTRACT = "/drive=d2/folder=legal/file=contract";
const BOARD_MINUTES = "/drive=d1/folder=board/file=minutes";
const TUESDAY = MONDAY + DAY;
const SATURDAY = MONDAY + 5 * DAY;

export const grantsBundleScenarios: readonly Scenario[] = [
  {
    id: "grants/bundles-two-teams",
    title:
      "Two teams give the same role at the same place, and only a team excluded in the archives loses it there",
    proves: ["D4", "D8"],
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:write": ["report:read"] },
      presets: { writer: ["report:read", "report:write"] },
      places: { "/": ["org"], "org": ["area"] },
    },
    statements: [
      assign("blue", "writer", ACME),
      assign("red", "writer", ACME),
      assign("green", "writer", ACME),
      exclude("blue", "report:write", ARCHIVES),
      exclude("green", "report:write", ARCHIVES),
    ],
    steps: [
      issue(MONDAY, "joe", "joe", { groups: ["blue", "red"] }),
      ask(
        MONDAY,
        { subject: "joe", groups: ["blue", "red"], permission: "report:write", place: ARCHIVES },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "kip", groups: ["blue"], permission: "report:write", place: ARCHIVES },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "lou", groups: ["blue", "green"], permission: "report:write", place: ARCHIVES },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY,
        { subject: "lou", groups: ["blue", "green"], permission: "report:write", place: ACME },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      write({ save: [exclude("red", "report:write", ARCHIVES)] }),
      ask(
        TUESDAY,
        { subject: "joe", groups: ["blue", "red"], permission: "report:write", place: ARCHIVES },
        "denied",
        {
          issuedAt: TUESDAY,
        },
      ),
      read(TUESDAY, "joe", { permission: "report:write", place: ARCHIVES }, "allowed"),
      ask(
        TUESDAY,
        { subject: "joe", groups: ["blue", "red"], permission: "report:read", place: ARCHIVES },
        "allowed",
        {
          issuedAt: TUESDAY,
        },
      ),
    ],
  },
  {
    id: "grants/permanent-manager-carries-no-restriction",
    title:
      "Grants of a permanent manager, directly or through a group, carry no deny and no exclusion placed on them",
    proves: ["D9", "D8"],
    catalog: {
      permissions: ["report:read", "report:write", "access:manage"],
      manager: "access:manage",
      places: { "/": ["org"], "org": ["unit"] },
    },
    statements: [
      allow("owner", "*"),
      deny("owner", "report:read", ACME),
      exclude("owner", "report:write", ACME),
      allow("ops", "*"),
      exclude("ops", "report:write", ACME),
      deny("uri", "report:read", ACME),
      allow("rob", "*", "/", FRIDAY_MIDNIGHT),
      deny("rob", "report:read", ACME),
    ],
    steps: [
      issue(MONDAY, "owner", "owner"),
      issue(MONDAY, "uri", "uri", { groups: ["ops"] }),
      issue(MONDAY, "rob", "rob"),
      read(TUESDAY, "owner", { permission: "report:read", place: "/org=acme/unit=u1" }, "allowed"),
      read(TUESDAY, "owner", { permission: "report:write", place: ACME }, "allowed"),
      read(TUESDAY, "uri", { permission: "report:read", place: ACME }, "allowed"),
      read(TUESDAY, "uri", { permission: "report:write", place: ACME }, "allowed"),
      read(TUESDAY, "rob", { permission: "report:read", place: ACME }, "denied"),
      read(TUESDAY, "rob", { permission: "report:write", place: ACME }, "allowed"),
      read(SATURDAY, "rob", { permission: "report:write", place: ACME }, "denied"),
      write({
        remove: [{ kind: "allow", subject: "owner", value: "*" }],
        save: [allow("owner", "report:*")],
      }),
      ask(SATURDAY, { subject: "owner", permission: "report:read", place: ACME }, "denied", {
        issuedAt: SATURDAY,
      }),
      read(SATURDAY, "owner", { permission: "report:read", place: ACME }, "allowed"),
    ],
  },
  {
    id: "grants/shared-drive",
    title:
      "A shared drive: new files readable at once, a two-hour share ends by itself, a drive-only session, a limited folder, a move",
    proves: ["D8", "D5", "D1"],
    catalog: {
      permissions: ["file:read", "file:edit", "limited-file:read", "billing:read"],
      presets: { viewer: ["file:read"] },
      places: {
        "/": ["drive", "area"],
        "drive": ["folder"],
        "folder": ["folder", "file"],
        "area": ["page"],
      },
    },
    statements: [
      assign("marketing", "viewer", D1),
      allow("sue", "file:read", CONTRACT, MONDAY + 2 * HOUR),
      allow("rae", "limited-file:read", "/drive=d1/folder=board"),
      assign("ned", "viewer", "/drive=d2"),
      deny("ned", "file:read", D1),
      allow("ned", "file:edit", "/drive=d1/folder=plans"),
    ],
    steps: [
      issue(MONDAY, "sue", "sue", { groups: ["marketing"] }),
      issue(MONDAY, "pat", "pat", { groups: ["marketing"], bases: [D1] }),
      read(
        MONDAY + 600,
        "pat",
        { permission: "file:read", place: "/drive=d1/folder=new/file=added" },
        "allowed",
      ),
      read(MONDAY + 3 * HOUR, "sue", { permission: "file:read", place: CONTRACT }, "denied"),
      ask(
        MONDAY + 3 * HOUR,
        { subject: "sue", groups: ["marketing"], permission: "file:read", place: CONTRACT },
        "denied",
      ),
      read(
        MONDAY + 3 * HOUR,
        "sue",
        { permission: "file:read", place: "/drive=d1/folder=reports/file=q3" },
        "allowed",
      ),
      read(
        MONDAY + 3 * HOUR,
        "pat",
        { permission: "billing:read", place: "/area=platform/page=billing" },
        "not-covered",
      ),
      ask(
        MONDAY + 3 * HOUR,
        {
          subject: "pat",
          groups: ["marketing"],
          permission: "limited-file:read",
          place: BOARD_MINUTES,
        },
        "denied",
        { issuedAt: MONDAY, bases: [D1] },
      ),
      ask(
        MONDAY + 3 * HOUR,
        { subject: "rae", permission: "limited-file:read", place: BOARD_MINUTES },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        MONDAY + 3 * HOUR,
        { subject: "ned", permission: "file:read", place: "/drive=d1/folder=plans" },
        "denied",
      ),
      write({
        remove: [
          { kind: "allow", subject: "ned", value: "file:edit", place: "/drive=d1/folder=plans" },
        ],
        save: [allow("ned", "file:edit", "/drive=d2/folder=plans")],
      }),
      ask(
        MONDAY + 4 * HOUR,
        { subject: "ned", permission: "file:read", place: "/drive=d2/folder=plans" },
        "allowed",
        {
          issuedAt: MONDAY + 4 * HOUR,
        },
      ),
      ask(
        MONDAY + 4 * HOUR,
        { subject: "ned", permission: "file:edit", place: "/drive=d2/folder=plans" },
        "allowed",
      ),
    ],
  },
];
