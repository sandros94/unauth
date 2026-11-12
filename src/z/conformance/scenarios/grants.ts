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
  issue,
  read,
  write,
} from "./_internal/steps.ts";

const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";
const HR_FOLDER = "/drive=d1/folder=hr";

const TUESDAY = MONDAY + DAY;
const THURSDAY = MONDAY + 3 * DAY;
const SATURDAY = MONDAY + 5 * DAY;

const writers: CatalogData = {
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { writer: ["report:read", "report:write"] },
  places: { "/": ["org"], "org": ["area"] },
};

/** Tuesday 2026-12-01 00:00 UTC, the end of the month. */
const DEC_1 = 1796083200;

export const grantsScenarios: readonly Scenario[] = [
  {
    id: "grants/sue-thursday-and-saturday",
    title:
      "Sue's team is excluded from writing in the archives, her own allow ends Friday, and nothing is issued again",
    proves: ["G8", "G4"],
    catalog: writers,
    statements: [
      assign("team", "writer", ACME),
      exclude("team", "report:write", ARCHIVES),
      allow("sue", "report:write", ACME, FRIDAY_MIDNIGHT),
    ],
    steps: [
      issue(MONDAY, "sue", "sue", { groups: ["team"] }),
      read(THURSDAY, "sue", { permission: "report:write", place: ARCHIVES }, "allowed"),
      ask(
        THURSDAY,
        { subject: "sue", groups: ["team"], permission: "report:write", place: ARCHIVES },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      read(SATURDAY, "sue", { permission: "report:write", place: ARCHIVES }, "denied"),
      ask(
        SATURDAY,
        { subject: "sue", groups: ["team"], permission: "report:write", place: ARCHIVES },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      read(SATURDAY, "sue", { permission: "report:write", place: ACME }, "allowed"),
      read(SATURDAY, "sue", { permission: "report:read", place: ARCHIVES }, "allowed"),
      ask(
        SATURDAY,
        { subject: "tess", groups: ["team"], permission: "report:write", place: ARCHIVES },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        SATURDAY,
        {
          subject: "tess",
          groups: ["team"],
          permission: "report:write",
          place: "/org=acme/area=sales",
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
    ],
  },
  {
    id: "grants/sue-excluded-herself",
    title: "Had the exclusion been placed on Sue herself, it would take her own allow out too",
    proves: ["G4", "G8"],
    catalog: writers,
    statements: [
      assign("team", "writer", ACME),
      exclude("sue", "report:write", ARCHIVES),
      allow("sue", "report:write", ACME, FRIDAY_MIDNIGHT),
    ],
    steps: [
      issue(MONDAY, "sue", "sue", { groups: ["team"] }),
      read(THURSDAY, "sue", { permission: "report:write", place: ARCHIVES }, "denied"),
      ask(
        THURSDAY,
        { subject: "sue", groups: ["team"], permission: "report:write", place: ARCHIVES },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      read(THURSDAY, "sue", { permission: "report:write", place: ACME }, "allowed"),
      read(THURSDAY, "sue", { permission: "report:read", place: ARCHIVES }, "allowed"),
    ],
  },
  {
    id: "grants/read-before-issue",
    title: "A replica whose clock runs behind is refused grants stamped after its own time",
    proves: ["G8"],
    catalog: { permissions: ["report:read"] },
    statements: [allow("kim", "report:read", ACME)],
    steps: [
      issue(MONDAY + HOUR, "kim-a", "kim"),
      read(MONDAY + HOUR, "kim-a", { permission: "report:read", place: ACME }, "allowed"),
      read(
        MONDAY + HOUR - 1,
        "kim-a",
        { permission: "report:read", place: ACME },
        "ERR_AUTHZ_GRANTS_EARLY",
      ),
      issue(MONDAY + 2 * HOUR, "kim-b", "kim", { bases: [ACME] }),
      read(
        MONDAY + 2 * HOUR - 1,
        ["kim-a", "kim-b"],
        { permission: "report:read", place: ACME },
        "ERR_AUTHZ_GRANTS_EARLY",
      ),
      read(
        MONDAY + 2 * HOUR,
        ["kim-a", "kim-b"],
        { permission: "report:read", place: ACME },
        "allowed",
      ),
    ],
  },
  {
    id: "grants/bases-and-not-covered",
    title:
      "Grants issued for one organisation speak for it alone, and carry what was stated above it",
    proves: ["G8"],
    catalog: {
      permissions: ["report:read", "report:write", "billing:read"],
      places: { "/": ["org"], "org": ["unit"] },
    },
    statements: [
      allow("cy", "report:read"),
      allow("cy", "report:write", ACME),
      deny("cy", "report:write", "/", MONDAY + 2 * DAY),
      deny("cy", "report:read", "/org=acme/unit=u9"),
      allow("cy", "billing:read", "/org=globex"),
    ],
    steps: [
      issue(MONDAY, "acme", "cy", { bases: [ACME] }),
      read(
        MONDAY + HOUR,
        "acme",
        { permission: "report:read", place: "/org=acme/unit=u3" },
        "allowed",
      ),
      read(
        MONDAY + HOUR,
        "acme",
        { permission: "report:read", place: "/org=acme/unit=u9" },
        "denied",
      ),
      read(MONDAY + HOUR, "acme", { permission: "report:write", place: ACME }, "denied"),
      read(
        MONDAY + HOUR,
        "acme",
        { permission: "billing:read", place: "/org=globex" },
        "not-covered",
      ),
      ask(
        MONDAY + HOUR,
        { subject: "cy", permission: "billing:read", place: "/org=globex" },
        "allowed",
        {
          issuedAt: MONDAY,
          bases: [ACME],
          fromGrants: "not-covered",
        },
      ),
      read(MONDAY + HOUR, "acme", { permission: "report:read", place: "/" }, "not-covered"),
      read(
        MONDAY + HOUR,
        "acme",
        { permission: "report:read", place: "/org=acme-x" },
        "not-covered",
      ),
      read(THURSDAY, "acme", { permission: "report:write", place: ACME }, "allowed"),
      ask(THURSDAY, { subject: "cy", permission: "report:write", place: ACME }, "allowed", {
        issuedAt: MONDAY,
        bases: [ACME],
      }),
      issue(THURSDAY, "two", "cy", { bases: ["/org=acme/unit=u3", "/org=globex"] }),
      read(THURSDAY, "two", { permission: "billing:read", place: "/org=globex" }, "allowed"),
      read(THURSDAY, "two", { permission: "report:read", place: ACME }, "not-covered"),
      read(THURSDAY, "two", { permission: "report:read", place: "/org=acme/unit=u3" }, "allowed"),
    ],
  },
  {
    id: "grants/two-sets-read-together",
    title:
      "A platform cookie and a drive session are read together, and an older set's deny stands",
    proves: ["G8"],
    catalog: {
      permissions: ["page:read", "file:read", "file:edit"],
      places: { "/": ["area", "drive"], "area": ["page"], "drive": ["folder"] },
    },
    statements: [
      allow("nia", "page:read", "/area=platform"),
      allow("nia", "file:read", "/drive=d1"),
      allow("nia", "file:edit", "/drive=d1"),
      deny("nia", "file:edit", HR_FOLDER),
    ],
    steps: [
      issue(MONDAY, "cookie", "nia", { bases: ["/area=platform"] }),
      issue(MONDAY, "drive", "nia", { bases: ["/drive=d1"] }),
      issue(MONDAY, "wide", "nia"),
      read(
        MONDAY + HOUR,
        ["cookie", "drive"],
        { permission: "page:read", place: "/area=platform/page=home" },
        "allowed",
      ),
      read(
        MONDAY + HOUR,
        ["cookie", "drive"],
        { permission: "file:read", place: "/drive=d1/folder=x" },
        "allowed",
      ),
      read(
        MONDAY + HOUR,
        ["cookie", "drive"],
        { permission: "file:read", place: "/drive=d2" },
        "not-covered",
      ),
      read(
        MONDAY + HOUR,
        ["cookie", "drive"],
        { permission: "file:edit", place: HR_FOLDER },
        "denied",
      ),
      write({ remove: [{ kind: "deny", subject: "nia", value: "file:edit", place: HR_FOLDER }] }),
      issue(TUESDAY, "fresh", "nia", { bases: ["/drive=d1"] }),
      read(TUESDAY, ["wide", "fresh"], { permission: "file:edit", place: HR_FOLDER }, "denied"),
      read(TUESDAY, ["cookie", "fresh"], { permission: "file:edit", place: HR_FOLDER }, "allowed"),
      ask(TUESDAY, { subject: "nia", permission: "file:edit", place: HR_FOLDER }, "allowed"),
      read(
        TUESDAY,
        ["wide", "fresh"],
        { permission: "page:read", place: "/area=platform/page=home" },
        "allowed",
      ),
    ],
  },
  {
    id: "grants/bundles-two-teams",
    title:
      "Two teams give the same role at the same place, and only a team excluded in the archives loses it there",
    proves: ["G4", "G8"],
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
    id: "grants/extended-then-shortened",
    title:
      "Dana's access is extended to the end of the month, then cut short: grants keep the end they were issued with",
    proves: ["G8"],
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:write": ["report:read"] },
      places: { "/": ["org"] },
    },
    statements: [allow("dana", "report:read", ACME, FRIDAY_MIDNIGHT)],
    steps: [
      issue(MONDAY, "monday", "dana"),
      ask(THURSDAY, { subject: "dana", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      write({ save: [allow("dana", "report:read", ACME, DEC_1)] }),
      ask(SATURDAY, { subject: "dana", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: THURSDAY + HOUR,
      }),
      read(SATURDAY, "monday", { permission: "report:read", place: ACME }, "denied"),
      issue(SATURDAY, "saturday", "dana"),
      write({ save: [allow("dana", "report:read", ACME, SATURDAY + 2 * DAY)] }),
      ask(
        SATURDAY + 2 * DAY,
        { subject: "dana", permission: "report:read", place: ACME },
        "denied",
        { issuedAt: SATURDAY + HOUR },
      ),
      read(SATURDAY + 2 * DAY, "saturday", { permission: "report:read", place: ACME }, "allowed"),
      write({ save: [allow("dana", "report:write", ACME, TUESDAY)] }),
      ask(
        SATURDAY + 2 * DAY,
        { subject: "dana", permission: "report:write", place: ACME },
        "denied",
        { issuedAt: SATURDAY + 2 * DAY },
      ),
      read(DEC_1, "saturday", { permission: "report:read", place: ACME }, "denied"),
    ],
  },
];
