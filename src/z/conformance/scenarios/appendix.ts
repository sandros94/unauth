import type { CatalogData } from "../../catalog.ts";
import type { Scenario } from "../types.ts";
import {
  DAY,
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

const SITE = "/org=forge/project=site";
const WWW = "/org=forge/project=site/repo=www";
const API = "/org=forge/project=site/repo=api";
const DOCS = "/org=forge/project=docs";
const ACME = "/org=acme";
const GLOBEX = "/org=globex";
const LOGS = "/org=acme/area=logs";
const SALES = "/org=acme/area=sales";
const ARCHIVES = "/org=acme/area=archives";
const ARCHIVE_2019 = "/org=acme/area=archives/archive=2019";
const ARCHIVE_2024 = "/org=acme/area=archives/archive=2024";
const D1 = "/drive=d1";
const CONTRACT = "/drive=d2/folder=legal/file=contract";
const BOARD_MINUTES = "/drive=d1/folder=board/file=minutes";
const PAYMENTS = "/cluster=prod/namespace=payments";
const SEARCH = "/cluster=prod/namespace=search";
const ARENA = "/server=arena";

const MINUTE = 60;
const NEXT_MONTH = MONDAY + 30 * DAY;
const TUESDAY = MONDAY + DAY;
const THURSDAY = MONDAY + 3 * DAY;

const forge: CatalogData = {
  permissions: [
    "access:manage",
    "code:read",
    "code:write",
    "issue:read",
    "issue:write",
    "release:publish",
  ],
  implies: { "code:write": ["code:read"], "issue:write": ["issue:read"] },
  presets: { developer: ["code:write", "issue:write"], writer: ["code:write"] },
  places: { "/": ["org"], "org": ["project"], "project": ["repo"] },
};

const cloud: CatalogData = {
  permissions: [
    "access:manage",
    "audit-log:delete",
    "audit-log:read",
    "report:read",
    "report:write",
  ],
  implies: { "report:write": ["report:read"] },
  places: { "/": ["org"], "org": ["area"], "area": ["archive"] },
};

export const appendixScenarios: readonly Scenario[] = [
  {
    id: "appendix/a1-person-and-assistant",
    title: "Ed is allowed everything, his assistant reads and drafts, and publishes once allowed",
    proves: ["G1", "G8"],
    catalog: { permissions: ["post:draft", "post:publish", "post:read"], places: false },
    statements: [
      allow("ed", "*"),
      allow("assistant", "post:read"),
      allow("assistant", "post:draft"),
    ],
    steps: [
      ask(MONDAY, { subject: "assistant", permission: "post:read" }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "assistant", permission: "post:draft" }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "assistant", permission: "post:publish" }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "ed", permission: "post:publish" }, "allowed", { issuedAt: MONDAY }),
      issue(MONDAY, "assistant", "assistant"),
      write({ save: [allow("assistant", "post:publish")] }),
      ask(MONDAY + HOUR, { subject: "assistant", permission: "post:publish" }, "allowed", {
        issuedAt: MONDAY + HOUR,
      }),
      read(MONDAY + HOUR, "assistant", { permission: "post:publish" }, "denied"),
    ],
  },
  {
    id: "appendix/a2-code-forge",
    title:
      "A team writes in one repository, Lea develops across her project, and Mel's cookie outlives her access for its hour",
    proves: ["G1", "G5", "G8"],
    catalog: forge,
    statements: [
      assign("web-team", "writer", WWW),
      assign("lea", "developer", SITE),
      allow("mel", "access:manage", SITE),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "ari", groups: ["web-team"], permission: "code:write", place: WWW },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "ari", groups: ["web-team"], permission: "code:write", place: API },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "lea", permission: "issue:write", place: API }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "lea", permission: "code:read", place: SITE }, "allowed"),
      ask(MONDAY, { subject: "lea", permission: "code:write", place: DOCS }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "lea", permission: "release:publish", place: WWW }, "denied"),
      issue(MONDAY, "mel-cookie", "mel", { bases: [SITE] }),
      write({ remove: [{ kind: "allow", subject: "mel", value: "access:manage", place: SITE }] }),
      ask(
        MONDAY + 6 * MINUTE,
        { subject: "mel", permission: "access:manage", place: SITE },
        "denied",
        { issuedAt: MONDAY + 6 * MINUTE, bases: [SITE] },
      ),
      read(
        MONDAY + 6 * MINUTE,
        "mel-cookie",
        { permission: "access:manage", place: SITE },
        "allowed",
      ),
      read(
        MONDAY + 6 * MINUTE,
        "mel-cookie",
        { permission: "access:manage", place: WWW },
        "allowed",
      ),
      read(
        MONDAY + 6 * MINUTE,
        "mel-cookie",
        { permission: "access:manage", place: DOCS },
        "not-covered",
      ),
    ],
  },
  {
    id: "appendix/a3-members-and-the-owner",
    title:
      "A ban on acme's members reaches Tom and next month's joiner, not the owner's own people, and a deny reaches the owner too",
    proves: ["G2", "G3", "G8"],
    catalog: cloud,
    statements: [
      allow("owner", "*"),
      allow("sre", "*"),
      allow("tom", "*", ACME),
      deny("acme-members", "audit-log:delete", ACME),
    ],
    steps: [
      ask(
        MONDAY,
        { subject: "tom", groups: ["acme-members"], permission: "audit-log:delete", place: LOGS },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        MONDAY,
        { subject: "tom", groups: ["acme-members"], permission: "audit-log:read", place: LOGS },
        "allowed",
      ),
      ask(MONDAY, { subject: "sre", permission: "audit-log:delete", place: LOGS }, "allowed", {
        issuedAt: MONDAY,
      }),
      write({ save: [allow("nina", "*", ACME)] }),
      ask(
        NEXT_MONTH,
        { subject: "nina", groups: ["acme-members"], permission: "audit-log:delete", place: ACME },
        "denied",
        { issuedAt: NEXT_MONTH },
      ),
      ask(
        NEXT_MONTH,
        { subject: "nina", groups: ["acme-members"], permission: "report:write", place: ACME },
        "allowed",
      ),
      ask(NEXT_MONTH, { subject: "owner", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      issue(NEXT_MONTH, "owner-before", "owner"),
      write({ save: [deny("owner", "report:read", ACME)] }),
      ask(
        NEXT_MONTH + HOUR,
        { subject: "owner", permission: "report:read", place: SALES },
        "denied",
        { issuedAt: NEXT_MONTH + HOUR },
      ),
      ask(
        NEXT_MONTH + HOUR,
        { subject: "owner", permission: "report:write", place: ACME },
        "denied",
        { issuedAt: NEXT_MONTH + HOUR },
      ),
      ask(
        NEXT_MONTH + HOUR,
        { subject: "owner", permission: "audit-log:delete", place: ACME },
        "allowed",
        { issuedAt: NEXT_MONTH + HOUR },
      ),
      ask(
        NEXT_MONTH + HOUR,
        { subject: "owner", permission: "report:read", place: GLOBEX },
        "allowed",
        { issuedAt: NEXT_MONTH + HOUR },
      ),
      read(
        NEXT_MONTH + HOUR,
        "owner-before",
        { permission: "report:read", place: ACME },
        "allowed",
      ),
    ],
  },
  {
    id: "appendix/a3-dan-in-the-archives",
    title:
      "Dan, allowed everything at acme, is denied reports in the archives, then excluded there and given one archive back",
    proves: ["G2", "G7", "G4", "G8"],
    catalog: cloud,
    statements: [allow("dan", "*", ACME), deny("dan", "report:read", ARCHIVES)],
    steps: [
      issue(MONDAY, "dan-monday", "dan"),
      ask(MONDAY, { subject: "dan", permission: "report:read", place: ARCHIVE_2019 }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "dan", permission: "report:read", place: SALES }, "allowed", {
        issuedAt: MONDAY,
      }),
      write({ save: [allow("dan", "report:read", ARCHIVE_2024)] }),
      ask(
        MONDAY + HOUR,
        { subject: "dan", permission: "report:read", place: ARCHIVE_2024 },
        "denied",
        { issuedAt: MONDAY + HOUR },
      ),
      write({
        remove: [{ kind: "deny", subject: "dan", value: "report:read", place: ARCHIVES }],
        save: [exclude("dan", "report:read", ARCHIVES)],
      }),
      ask(
        MONDAY + 2 * HOUR,
        { subject: "dan", permission: "report:read", place: ARCHIVE_2024 },
        "allowed",
        { issuedAt: MONDAY + 2 * HOUR },
      ),
      ask(
        MONDAY + 2 * HOUR,
        { subject: "dan", permission: "report:read", place: ARCHIVE_2019 },
        "denied",
        { issuedAt: MONDAY + 2 * HOUR },
      ),
      ask(
        MONDAY + 2 * HOUR,
        { subject: "dan", permission: "report:write", place: ARCHIVE_2024 },
        "denied",
        { issuedAt: MONDAY + 2 * HOUR },
      ),
      ask(
        MONDAY + 2 * HOUR,
        { subject: "dan", permission: "report:write", place: SALES },
        "allowed",
        { issuedAt: MONDAY + 2 * HOUR },
      ),
      read(
        MONDAY + 2 * HOUR,
        "dan-monday",
        { permission: "report:read", place: ARCHIVE_2024 },
        "denied",
      ),
      read(
        MONDAY + 2 * HOUR,
        "dan-monday",
        { permission: "report:write", place: SALES },
        "allowed",
      ),
    ],
  },
  {
    id: "appendix/a4-shared-drive",
    title:
      "A shared drive: new files readable at once, a two-hour share ends by itself, a drive-only session, a limited folder, a move",
    proves: ["G8", "G5", "G1"],
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
  {
    id: "appendix/a7-cluster",
    title:
      "Groups come from outside, their statements read with each question: a binding in one namespace reaches only it, one on the cluster every namespace",
    proves: ["G1", "G5"],
    catalog: {
      permissions: ["pod:read", "pod:delete", "secret:read", "report:read"],
      presets: { view: ["pod:read"], admin: ["pod:*", "secret:read"] },
      places: { "/": ["cluster", "org"], "cluster": ["namespace"] },
    },
    statements: [
      assign("team-a", "admin", PAYMENTS),
      assign("team-b", "view", "/cluster=prod"),
      assign("team-c", "admin", "/cluster=prod"),
      allow("alice", "report:read", "/org=acme"),
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
      ask(MONDAY, { subject: "alice", permission: "report:read", place: "/org=acme" }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "alice", permission: "report:read", place: "/org=acme-x" }, "denied", {
        issuedAt: MONDAY,
      }),
    ],
  },
  {
    id: "appendix/a5-chat-server",
    title:
      "Gil is banned from matches until next Monday, muted on the server but for the help room, and silenced in one channel",
    proves: ["G2", "G7", "G8"],
    catalog: {
      permissions: ["match:join", "chat:read", "chat:send", "slowmode-chat:send", "voice:send"],
      presets: {
        player: ["match:join", "chat:read", "chat:send", "slowmode-chat:send", "voice:send"],
      },
      places: { "/": ["server"], "server": ["channel"] },
    },
    statements: [
      assign("gil", "player", ARENA),
      deny("gil", "match:join", ARENA, MONDAY + 7 * DAY - 9 * HOUR),
      exclude("gil", "chat:send", ARENA),
      allow("gil", "chat:send", `${ARENA}/channel=help`),
      deny("gil", "*:send", `${ARENA}/channel=general`),
    ],
    steps: [
      issue(MONDAY, "gil", "gil"),
      read(THURSDAY, "gil", { permission: "match:join", place: ARENA }, "denied"),
      ask(THURSDAY, { subject: "gil", permission: "match:join", place: ARENA }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(
        THURSDAY,
        { subject: "gil", permission: "chat:send", place: `${ARENA}/channel=lobby` },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        THURSDAY,
        { subject: "gil", permission: "chat:send", place: `${ARENA}/channel=help` },
        "allowed",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        THURSDAY,
        { subject: "gil", permission: "slowmode-chat:send", place: `${ARENA}/channel=general` },
        "denied",
        { issuedAt: MONDAY },
      ),
      ask(
        THURSDAY,
        { subject: "gil", permission: "voice:send", place: `${ARENA}/channel=general` },
        "denied",
        {
          issuedAt: MONDAY,
        },
      ),
      ask(
        THURSDAY,
        { subject: "gil", permission: "voice:send", place: `${ARENA}/channel=lobby` },
        "allowed",
      ),
      ask(
        THURSDAY,
        { subject: "gil", permission: "chat:read", place: `${ARENA}/channel=general` },
        "allowed",
      ),
      read(MONDAY + 8 * DAY, "gil", { permission: "match:join", place: ARENA }, "allowed"),
      ask(MONDAY + 8 * DAY, { subject: "gil", permission: "match:join", place: ARENA }, "allowed"),
    ],
  },
  {
    id: "appendix/a6-workspace-of-pages",
    title:
      "Leads write in the archives, writers do not, Mona is excluded there herself, and Hal's new team counts once reissued",
    proves: ["G4", "G7", "G8"],
    catalog: {
      permissions: ["report:read", "report:write", "page:read", "page:edit"],
      implies: { "report:write": ["report:read"] },
      presets: {
        lead: ["report:*", "page:*"],
        writer: ["report:read", "report:write", "page:edit"],
      },
      places: {
        "/": ["org"],
        "org": ["area", "project"],
        "area": ["archive"],
        "project": ["report"],
      },
    },
    statements: [
      assign("leads", "lead", ACME),
      assign("writers", "writer", ACME),
      exclude("writers", "report:write", ARCHIVES),
      allow("zoe", "report:*", ACME),
      exclude("zoe", "report:write", ACME),
    ],
    steps: [
      ask(
        MONDAY,
        {
          subject: "mona",
          groups: ["leads", "writers"],
          permission: "report:write",
          place: `${ARCHIVES}/archive=2019`,
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
        {
          subject: "wes",
          groups: ["writers"],
          permission: "report:write",
          place: "/org=acme/project=p1/report=r1",
        },
        "allowed",
        { issuedAt: MONDAY },
      ),
      ask(MONDAY, { subject: "zoe", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "zoe", permission: "report:write", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      issue(MONDAY, "hal-writer", "hal", { groups: ["writers"] }),
      read(
        MONDAY,
        "hal-writer",
        { permission: "report:write", place: `${ARCHIVES}/archive=2019` },
        "denied",
      ),
      write({
        save: [
          exclude("mona", "report:write", ARCHIVES),
          allow("mona", "report:write", `${ARCHIVES}/archive=2024`),
        ],
      }),
      ask(
        TUESDAY,
        {
          subject: "mona",
          groups: ["leads", "writers"],
          permission: "report:write",
          place: `${ARCHIVES}/archive=2019`,
        },
        "denied",
        { issuedAt: TUESDAY },
      ),
      ask(
        TUESDAY,
        {
          subject: "mona",
          groups: ["leads", "writers"],
          permission: "report:write",
          place: `${ARCHIVES}/archive=2024`,
        },
        "allowed",
        { issuedAt: TUESDAY },
      ),
      ask(
        TUESDAY,
        {
          subject: "mona",
          groups: ["leads", "writers"],
          permission: "report:write",
          place: `${ARCHIVES}/archive=2027`,
        },
        "denied",
      ),
      ask(
        TUESDAY,
        {
          subject: "mona",
          groups: ["leads", "writers"],
          permission: "report:write",
          place: "/org=acme/project=p1/report=r1",
        },
        "allowed",
        { issuedAt: TUESDAY },
      ),
      ask(
        TUESDAY,
        {
          subject: "mona",
          groups: ["leads", "writers"],
          permission: "report:read",
          place: `${ARCHIVES}/archive=2019`,
        },
        "allowed",
        { issuedAt: TUESDAY },
      ),
      issue(TUESDAY, "hal-lead", "hal", { groups: ["writers", "leads"] }),
      read(
        TUESDAY,
        "hal-lead",
        { permission: "report:write", place: `${ARCHIVES}/archive=2019` },
        "allowed",
      ),
      read(
        TUESDAY,
        "hal-writer",
        { permission: "report:write", place: `${ARCHIVES}/archive=2019` },
        "denied",
      ),
    ],
  },
];
