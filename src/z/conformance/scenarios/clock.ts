import type { CatalogData } from "../../catalog.ts";
import type { Question } from "../engine.ts";
import type { ExpectedDiverged, ReadStep, Scenario, ScenarioQuestion } from "../types.ts";
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
} from "./_internal/steps.ts";

const ACME = "/org=acme";
const GLOBEX = "/org=globex";
const SERVER = "/server=s1";

const NEXT_MONDAY = MONDAY + 7 * DAY;
/** Five minutes, a clock tolerance an application might give a browser. */
const FIVE_MINUTES = 300;
/** Ten seconds, a clock tolerance an application might give between its servers. */
const TEN_SECONDS = 10;
/** Five seconds after Friday midnight, when the statements that ended then are a moment old. */
const JUST_AFTER = FRIDAY_MIDNIGHT + 5;

const chat: CatalogData = {
  permissions: ["chat:send", "event:host", "match:join"],
  presets: { player: ["chat:send", "match:join"] },
  places: { "/": ["server"], "server": ["channel"] },
};

const reports: CatalogData = {
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  places: { "/": ["org"] },
};

const kimReads: Question = { permission: "report:read", place: ACME };
const writes: Question = { permission: "report:write", place: ACME };

/**
 * Grants read under the clock tolerance the application gives a read, as `clockTolerance` (Section
 * 8.3 of the model), since the clock that reads grants is rarely the one that issued them. Under it
 * grants are read that much before their issue, and an end counts that much later, for a deny and
 * an exclusion as for an allow. A question asked of the statements and the issuing of grants take
 * none, so a read under a tolerance and a question asked at the same time differ on what ended
 * less than the tolerance before.
 */
export const clockScenarios: readonly Scenario[] = [
  {
    id: "grants/browser-clock-behind",
    title:
      "Kim's browser runs a few seconds behind the server that issued her grants: read within the clock tolerance it is given, refused beyond it",
    proves: ["G8"],
    catalog: { permissions: ["report:read"], places: { "/": ["org"] } },
    statements: [allow("kim", "report:read", ACME)],
    steps: [
      issue(MONDAY, "kim", "kim"),
      read(MONDAY - 1, "kim", kimReads, "ERR_AUTHZ_GRANTS_FUTURE"),
      readWith(5, MONDAY - 5, "kim", kimReads, "allowed", null),
      readWith(5, MONDAY - 6, "kim", kimReads, "ERR_AUTHZ_GRANTS_FUTURE"),
      readWith(30, MONDAY - 30, "kim", kimReads, "allowed", null),
      readWith(30, MONDAY - 31, "kim", kimReads, "ERR_AUTHZ_GRANTS_FUTURE"),
      issue(MONDAY + HOUR, "kim-globex", "kim", { bases: [GLOBEX] }),
      readWith(30, MONDAY + HOUR - 30, ["kim", "kim-globex"], kimReads, "allowed"),
      readWith(30, MONDAY + HOUR - 31, ["kim", "kim-globex"], kimReads, "ERR_AUTHZ_GRANTS_FUTURE"),
    ],
  },
  {
    id: "grants/reader-ahead-counts-what-just-ended",
    title:
      "Gil's grants are issued on Monday and read by a browser that runs ahead, given a clock tolerance of five minutes: what ended within the tolerance still counts, a deny as an allow, and a read given none sees it ended",
    proves: ["G8"],
    catalog: chat,
    statements: [
      assign("gil", "player", SERVER),
      deny("gil", "match:join", SERVER, NEXT_MONDAY),
      exclude("gil", "chat:send", SERVER, FRIDAY_MIDNIGHT),
      allow("gil", "event:host", SERVER, FRIDAY_MIDNIGHT),
    ],
    steps: [
      issue(MONDAY, "gil", "gil"),
      readWith(FIVE_MINUTES, FRIDAY_MIDNIGHT - 1, "gil", inLobby("chat:send"), "denied"),
      readWith(FIVE_MINUTES, FRIDAY_MIDNIGHT - 1, "gil", inLobby("event:host"), "allowed"),
      readWith(FIVE_MINUTES, FRIDAY_MIDNIGHT + 1, "gil", inLobby("chat:send"), "denied"),
      readWith(FIVE_MINUTES, FRIDAY_MIDNIGHT + 1, "gil", inLobby("event:host"), "allowed"),
      read(FRIDAY_MIDNIGHT + 1, "gil", inLobby("chat:send"), "allowed"),
      read(FRIDAY_MIDNIGHT + 1, "gil", inLobby("event:host"), "denied"),
      readWith(
        FIVE_MINUTES,
        FRIDAY_MIDNIGHT + FIVE_MINUTES,
        "gil",
        inLobby("chat:send"),
        "allowed",
      ),
      readWith(
        FIVE_MINUTES,
        FRIDAY_MIDNIGHT + FIVE_MINUTES,
        "gil",
        inLobby("event:host"),
        "denied",
      ),
      readWith(FIVE_MINUTES, NEXT_MONDAY + 1, "gil", inLobby("match:join"), "denied"),
      read(NEXT_MONDAY + 1, "gil", inLobby("match:join"), "allowed"),
      readWith(FIVE_MINUTES, NEXT_MONDAY + FIVE_MINUTES, "gil", inLobby("match:join"), "allowed"),
    ],
  },
  {
    id: "grants/tolerance-differs-from-the-statements",
    title:
      "Sue's allow of writing and Kim's suspension from it end on Friday: five seconds later the statements answer that Sue no longer writes and Kim does, a read under a clock tolerance of ten seconds answers the other way, a read under none answers as the statements, and ten seconds after the end all agree",
    proves: ["G8"],
    catalog: reports,
    statements: [
      allow("sue", "report:write", ACME, FRIDAY_MIDNIGHT),
      allow("kim", "report:*", ACME),
      deny("kim", "report:write", ACME, FRIDAY_MIDNIGHT),
    ],
    steps: [
      issue(MONDAY, "sue", "sue"),
      issue(MONDAY, "kim", "kim"),
      ask(JUST_AFTER, writer("sue"), "denied"),
      readWith(TEN_SECONDS, JUST_AFTER, "sue", writes, "allowed"),
      read(JUST_AFTER, "sue", writes, "denied"),
      ask(JUST_AFTER, writer("kim"), "allowed"),
      readWith(TEN_SECONDS, JUST_AFTER, "kim", writes, "denied"),
      read(JUST_AFTER, "kim", writes, "allowed"),
      ask(FRIDAY_MIDNIGHT + TEN_SECONDS, writer("sue"), "denied"),
      readWith(TEN_SECONDS, FRIDAY_MIDNIGHT + TEN_SECONDS, "sue", writes, "denied"),
      ask(FRIDAY_MIDNIGHT + TEN_SECONDS, writer("kim"), "allowed"),
      readWith(TEN_SECONDS, FRIDAY_MIDNIGHT + TEN_SECONDS, "kim", writes, "allowed"),
    ],
  },
];

/** A read under a clock tolerance of `tolerance` seconds. */
function readWith(
  tolerance: number,
  at: number,
  grants: ReadStep["grants"],
  question: Question,
  expect: ReadStep["expect"],
  told?: ExpectedDiverged,
): ReadStep {
  return { ...read(at, grants, question, expect, told), clockTolerance: tolerance };
}

/** `subject` asks to write at the organisation. */
function writer(subject: string): ScenarioQuestion {
  return { subject, ...writes };
}

/** `permission` in the lobby of the server. */
function inLobby(permission: string): Question {
  return { permission, place: `${SERVER}/channel=lobby` };
}
