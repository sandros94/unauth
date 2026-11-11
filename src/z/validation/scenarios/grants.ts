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
} from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";
const PROJECT = "/org=forge/project=web";
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

export const grantsScenarios: readonly Scenario[] = [
  {
    id: "grants/sue-thursday-and-saturday",
    title:
      "Sue's team is excluded from writing in the archives, her own allow ends Friday, and nothing is issued again",
    proves: ["D8", "D4"],
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
    proves: ["D4", "D8"],
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
    proves: ["D8"],
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
    id: "grants/frozen-against-a-change",
    title:
      "Mel's management is removed: her cookie still carries it minutes later, the statements no longer do",
    proves: ["D8"],
    catalog: {
      permissions: ["repo:read", "repo:write", "access:manage"],
      presets: { developer: ["repo:read", "repo:write"] },
      places: { "/": ["org"], "org": ["project"] },
      manager: "access:manage",
    },
    statements: [
      allow("owner", "*"),
      allow("mel", "access:manage", PROJECT),
      assign("mel", "developer", PROJECT),
    ],
    steps: [
      issue(MONDAY, "mel-cookie", "mel"),
      {
        step: "change",
        at: MONDAY + 300,
        author: "owner",
        change: { action: "remove", statement: allow("mel", "access:manage", PROJECT) },
        expect: "accepted",
      },
      read(MONDAY + 360, "mel-cookie", { permission: "access:manage", place: PROJECT }, "allowed"),
      ask(MONDAY + 360, { subject: "mel", permission: "access:manage", place: PROJECT }, "denied"),
      ask(MONDAY + 360, { subject: "mel", permission: "repo:write", place: PROJECT }, "allowed"),
      write({ remove: [{ kind: "assign", subject: "mel", value: "developer", place: PROJECT }] }),
      read(MONDAY + 600, "mel-cookie", { permission: "repo:write", place: PROJECT }, "allowed"),
      ask(MONDAY + 600, { subject: "mel", permission: "repo:write", place: PROJECT }, "denied"),
      issue(MONDAY + HOUR, "mel-fresh", "mel"),
      read(MONDAY + HOUR, "mel-fresh", { permission: "access:manage", place: PROJECT }, "denied"),
      read(MONDAY + HOUR, "mel-fresh", { permission: "repo:read", place: PROJECT }, "denied"),
    ],
  },
  {
    id: "grants/bases-and-not-covered",
    title:
      "Grants issued for one organisation speak for it alone, and carry what was stated above it",
    proves: ["D8"],
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
    proves: ["D8"],
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
];
