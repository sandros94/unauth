import type { Scenario } from "../types.ts";
import {
  ACME,
  BLOG,
  CLOUD,
  DAY,
  DEC_1,
  DOCS,
  FORGE,
  FORGE_ORG,
  FRIDAY,
  HOUR,
  MINUTE,
  MONDAY,
  SITE,
  WWW,
  allow,
  ask,
  assign,
  deny,
  genesis,
  place,
  remove,
} from "./_internal/authority.ts";

export const authorityAppendixScenarios: readonly Scenario[] = [
  {
    id: "authority/appendix/a1-person-and-assistant",
    title: "Ed signs in first and lets his assistant read and draft, then publish",
    proves: ["A5", "A3", "A2"],
    catalog: BLOG,
    steps: [
      genesis(MONDAY, allow("ed", "*")),
      place({ at: MONDAY + MINUTE, author: "ed" }, allow("assistant", "post:read")),
      place({ at: MONDAY + MINUTE, author: "ed" }, allow("assistant", "post:draft")),
      ask({ at: MONDAY + HOUR, subject: "assistant" }, "post:read", "allowed"),
      ask({ at: MONDAY + HOUR, subject: "assistant" }, "post:draft", "allowed"),
      ask({ at: MONDAY + HOUR, subject: "assistant" }, "post:publish", "denied"),
      ask({ at: MONDAY + HOUR, subject: "ed" }, "post:publish", "allowed"),
      place({ at: MONDAY + 2 * HOUR, author: "assistant" }, allow("assistant", "post:publish"), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      ask({ at: MONDAY + 2 * HOUR, subject: "assistant" }, "post:publish", "denied"),
      place({ at: MONDAY + 3 * HOUR, author: "ed" }, allow("assistant", "post:publish")),
      ask({ at: MONDAY + 3 * HOUR, subject: "assistant" }, "post:publish", "allowed"),
    ],
  },
  {
    id: "authority/appendix/a2-lea-and-her-own-statements",
    title:
      "Lea leaves her developer role, and can neither lift a deny on herself nor take the role back",
    proves: ["A3"],
    catalog: FORGE,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, assign("web-team", "writer", { place: WWW })),
      place({ at: MONDAY + MINUTE, author: "owner" }, assign("lea", "developer", { place: SITE })),
      place({ at: MONDAY + MINUTE, author: "owner" }, deny("lea", "member:kick", { place: SITE })),
      remove(
        { at: MONDAY + HOUR, author: "lea", groups: ["web-team"] },
        assign("lea", "developer", { place: SITE }),
      ),
      ask(
        { at: MONDAY + HOUR + MINUTE, subject: "lea", groups: ["web-team"], place: SITE },
        "issue:write",
        "denied",
      ),
      remove(
        { at: MONDAY + 2 * HOUR, author: "lea", groups: ["web-team"] },
        deny("lea", "member:kick", { place: SITE }),
        ["not-manager", "not-held", "about-self"],
      ),
      place(
        { at: MONDAY + 2 * HOUR, author: "lea", groups: ["web-team"] },
        assign("lea", "developer", { place: SITE }),
        ["not-manager", "not-held", "about-self"],
      ),
      ask(
        { at: MONDAY + 3 * HOUR, subject: "lea", groups: ["web-team"], place: WWW },
        "code:write",
        "allowed",
      ),
    ],
  },
  {
    id: "authority/appendix/a2-mel-removed-a-moment-ago",
    title:
      "Mel loses her management, and her cookie still says she has it while the statements refuse her",
    proves: ["A1"],
    catalog: FORGE,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("mel", "access:manage", { place: SITE }),
      ),
      place({ at: MONDAY + MINUTE, author: "owner" }, assign("mel", "maintainer", { place: SITE })),
      { step: "issue", at: MONDAY + 2 * MINUTE, as: "mel-cookie", subject: "mel" },
      place(
        { at: MONDAY + 5 * MINUTE, author: "mel" },
        assign("mel-alt", "developer", { place: SITE }),
      ),
      remove(
        { at: MONDAY + 10 * MINUTE, author: "owner" },
        allow("mel", "access:manage", { place: SITE }),
      ),
      place(
        { at: MONDAY + 15 * MINUTE, author: "mel" },
        assign("mel-alt", "maintainer", { place: SITE }),
        ["not-manager"],
      ),
      {
        step: "read",
        at: MONDAY + 15 * MINUTE,
        grants: "mel-cookie",
        question: { permission: "access:manage", place: SITE },
        expect: "allowed",
      },
      {
        step: "read",
        at: MONDAY + 15 * MINUTE,
        grants: "mel-cookie",
        question: { permission: "code:read", place: SITE },
        expect: "allowed",
      },
      ask({ at: MONDAY + 15 * MINUTE, subject: "mel", place: SITE }, "access:manage", "denied"),
      ask({ at: MONDAY + 15 * MINUTE, subject: "mel-alt", place: SITE }, "member:kick", "denied"),
    ],
  },
  {
    id: "authority/appendix/a2-mia-and-the-owner",
    title: "A moderator cannot strip the organisation owner, who strips the moderators",
    proves: ["A4", "A1"],
    catalog: FORGE,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("founder", "*", { place: FORGE_ORG })),
      place(
        { at: MONDAY + HOUR, author: "founder" },
        allow("moderators", "access:manage", { place: FORGE_ORG }),
      ),
      place(
        { at: MONDAY + HOUR, author: "founder" },
        allow("moderators", "member:kick", { place: FORGE_ORG }),
      ),
      place(
        { at: MONDAY + 2 * HOUR, author: "mia", groups: ["moderators"] },
        allow("newbie", "member:kick", { place: SITE }),
      ),
      remove(
        { at: MONDAY + 2 * HOUR, author: "mia", groups: ["moderators"] },
        allow("founder", "*", { place: FORGE_ORG }),
        ["not-held"],
      ),
      remove(
        { at: MONDAY + 3 * HOUR, author: "founder" },
        allow("moderators", "access:manage", { place: FORGE_ORG }),
      ),
      remove(
        { at: MONDAY + 4 * HOUR, author: "mia", groups: ["moderators"] },
        allow("newbie", "member:kick", { place: SITE }),
        ["not-manager"],
      ),
      ask({ at: MONDAY + 5 * HOUR, subject: "founder", place: SITE }, "release:publish", "allowed"),
    ],
  },
  {
    id: "authority/appendix/a2-cal-until-the-end-of-the-month",
    title:
      "Cal maintains a project until the end of the month: what he gives ends then, his ban on a spammer does not",
    proves: ["A2"],
    catalog: FORGE,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("cal", "access:manage", { place: SITE, until: DEC_1 }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        assign("cal", "maintainer", { place: SITE, until: DEC_1 }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        assign("spammer", "developer", { place: FORGE_ORG }),
      ),
      place({ at: MONDAY + HOUR, author: "cal" }, assign("dana", "maintainer", { place: SITE }), [
        "not-held",
      ]),
      place(
        { at: MONDAY + HOUR, author: "cal" },
        assign("dana", "maintainer", { place: SITE, until: DEC_1 }),
      ),
      place({ at: MONDAY + HOUR, author: "cal" }, deny("spammer", "issue:write", { place: SITE })),
      ask({ at: FRIDAY, subject: "dana", place: SITE }, "release:publish", "allowed"),
      ask({ at: DEC_1 + DAY, subject: "dana", place: SITE }, "code:write", "denied"),
      ask({ at: DEC_1 + DAY, subject: "spammer", place: SITE }, "issue:write", "denied"),
      ask({ at: DEC_1 + DAY, subject: "spammer", place: DOCS }, "issue:write", "allowed"),
      remove({ at: DEC_1 + DAY, author: "cal" }, deny("spammer", "issue:write", { place: SITE }), [
        "not-manager",
        "not-held",
      ]),
    ],
  },
  {
    id: "authority/appendix/a3-tom-restricts-his-own-group",
    title:
      "Tom freezes report writing for every member of acme, himself included, and only the owner thaws it",
    proves: ["A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("deploy", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("tom", "*", { place: ACME })),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("sre", "audit-log:delete")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        deny("acme-members", "audit-log:delete", { place: ACME }),
      ),
      ask(
        { at: MONDAY + HOUR, subject: "tom", groups: ["acme-members"], place: ACME },
        "audit-log:delete",
        "denied",
      ),
      ask({ at: MONDAY + HOUR, subject: "sre", place: ACME }, "audit-log:delete", "allowed"),
      place(
        { at: MONDAY + 2 * HOUR, author: "tom", groups: ["acme-members"] },
        deny("acme-members", "report:write", { place: ACME }),
      ),
      ask(
        { at: MONDAY + 3 * HOUR, subject: "tom", groups: ["acme-members"], place: ACME },
        "report:write",
        "denied",
      ),
      remove(
        { at: MONDAY + 3 * HOUR, author: "tom", groups: ["acme-members"] },
        deny("acme-members", "report:write", { place: ACME }),
        ["not-held"],
      ),
      remove(
        { at: MONDAY + 4 * HOUR, author: "owner" },
        deny("acme-members", "report:write", { place: ACME }),
      ),
      ask(
        { at: MONDAY + 5 * HOUR, subject: "tom", groups: ["acme-members"], place: ACME },
        "report:write",
        "allowed",
      ),
      place({ at: MONDAY + 30 * DAY, author: "owner" }, allow("nina", "*", { place: ACME })),
      ask(
        { at: MONDAY + 30 * DAY + HOUR, subject: "nina", groups: ["acme-members"], place: ACME },
        "audit-log:delete",
        "denied",
      ),
      ask(
        { at: MONDAY + 30 * DAY + HOUR, subject: "nina", groups: ["acme-members"], place: ACME },
        "report:read",
        "allowed",
      ),
    ],
  },
  {
    id: "authority/appendix/a3-owner-and-deploy-job",
    title:
      "Denies on the owner and on a staff group that includes the deploy job reach neither, and the job lifts its own",
    proves: ["D9", "A1"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("deploy", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("tom", "*", { place: ACME })),
      place(
        { at: MONDAY + HOUR, author: "tom", groups: ["acme-members", "staff"] },
        deny("owner", "report:read", { place: ACME }),
      ),
      ask({ at: MONDAY + 2 * HOUR, subject: "owner", place: ACME }, "report:read", "allowed"),
      place({ at: MONDAY + 3 * HOUR, author: "owner" }, deny("staff", "access:manage")),
      ask(
        { at: MONDAY + 4 * HOUR, subject: "deploy", groups: ["staff"], place: ACME },
        "access:manage",
        "allowed",
      ),
      ask(
        { at: MONDAY + 4 * HOUR, subject: "tom", groups: ["acme-members", "staff"], place: ACME },
        "access:manage",
        "denied",
      ),
      place(
        { at: MONDAY + 4 * HOUR, author: "tom", groups: ["acme-members", "staff"] },
        allow("ike", "report:read", { place: ACME }),
        ["not-manager"],
      ),
      remove(
        { at: MONDAY + 5 * HOUR, author: "deploy", groups: ["staff"] },
        deny("staff", "access:manage"),
      ),
      place(
        { at: MONDAY + 6 * HOUR, author: "tom", groups: ["acme-members", "staff"] },
        allow("ike", "report:read", { place: ACME }),
      ),
      ask({ at: MONDAY + 7 * HOUR, subject: "ike", place: ACME }, "report:read", "allowed"),
    ],
  },
];
