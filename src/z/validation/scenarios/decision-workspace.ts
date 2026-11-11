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
} from "./_internal/scenario-steps.ts";

const ACME = "/org=acme";
const ARCHIVES = "/org=acme/area=archives";
const ARENA = "/server=arena";
const TUESDAY = MONDAY + DAY;
const THURSDAY = MONDAY + 3 * DAY;

export const decisionWorkspaceScenarios: readonly Scenario[] = [
  {
    id: "decision/chat-server",
    title:
      "Gil is banned from matches until next Monday, muted on the server but for the help room, and silenced in one channel",
    proves: ["D2", "D7", "D8"],
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
    id: "decision/workspace-of-pages",
    title:
      "Leads write in the archives, writers do not, Mona is excluded there herself, and Hal's new team counts once reissued",
    proves: ["D4", "D7", "D8"],
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
