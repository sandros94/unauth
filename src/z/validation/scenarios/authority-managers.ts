import type { Scenario } from "../types.ts";
import {
  ACME,
  ARCHIVES,
  CLOUD,
  DAY,
  FRIDAY,
  HOUR,
  MINUTE,
  MONDAY,
  YEAR_2100,
  allow,
  ask,
  assign,
  deny,
  exclude,
  genesis,
  place,
  remove,
} from "./_internal/authority.ts";

export const authorityManagerScenarios: readonly Scenario[] = [
  {
    id: "authority/permanent/only-a-permanent-manager-places-one",
    title: "An owner by role holds everything yet cannot mint another root manager",
    proves: ["A2"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("ana", "*")),
      place({ at: MONDAY + MINUTE, author: "ana" }, assign("vic", "owner")),
      ask({ at: MONDAY + 2 * MINUTE, subject: "vic", place: ACME }, "org:own", "allowed"),
      place({ at: MONDAY + 3 * MINUTE, author: "vic" }, allow("deploy", "*"), ["not-held"]),
      place(
        { at: MONDAY + 4 * MINUTE, author: "vic" },
        allow("deploy", "*", { until: MONDAY + 7 * DAY }),
      ),
      ask({ at: MONDAY + 8 * DAY, subject: "deploy", place: ACME }, "report:delete", "denied"),
      place({ at: MONDAY + 8 * DAY, author: "ana" }, allow("deploy", "*")),
      ask({ at: MONDAY + 30 * DAY, subject: "deploy", place: ACME }, "report:delete", "allowed"),
    ],
  },
  {
    id: "authority/permanent/only-a-permanent-manager-removes-one",
    title: "An owner by role holds everything yet cannot take the root away from the deploy job",
    proves: ["A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("ana", "*")),
      place({ at: MONDAY + MINUTE, author: "ana" }, allow("deploy", "*")),
      place({ at: MONDAY + 2 * MINUTE, author: "ana" }, assign("vic", "owner")),
      remove({ at: MONDAY + 3 * MINUTE, author: "vic" }, allow("deploy", "*"), ["not-held"]),
      place(
        { at: MONDAY + 3 * MINUTE, author: "vic" },
        allow("deploy", "*", { until: MONDAY + 7 * DAY }),
        ["not-held"],
      ),
      ask({ at: MONDAY + 4 * MINUTE, subject: "deploy", place: ACME }, "report:delete", "allowed"),
      remove({ at: MONDAY + 5 * MINUTE, author: "ana" }, allow("deploy", "*")),
      ask({ at: MONDAY + 6 * MINUTE, subject: "deploy", place: ACME }, "report:delete", "denied"),
    ],
  },
  {
    id: "authority/permanent/the-last-one-stays",
    title: "The founder cannot leave until a deploy job holds the root, then the job cannot leave",
    proves: ["A7"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("ana", "*")),
      remove({ at: MONDAY + MINUTE, author: "ana" }, allow("ana", "*"), ["last-manager"]),
      place({ at: MONDAY + 2 * MINUTE, author: "ana" }, allow("ana", "*", { until: FRIDAY }), [
        "about-self",
        "last-manager",
      ]),
      ask({ at: FRIDAY + DAY, subject: "ana", place: ACME }, "report:read", "allowed"),
      place({ at: FRIDAY + DAY, author: "ana" }, allow("deploy", "*")),
      remove({ at: FRIDAY + DAY + MINUTE, author: "ana" }, allow("ana", "*")),
      ask({ at: FRIDAY + DAY + 2 * MINUTE, subject: "ana", place: ACME }, "report:read", "denied"),
      ask(
        { at: FRIDAY + DAY + 2 * MINUTE, subject: "deploy", place: ACME },
        "report:read",
        "allowed",
      ),
      remove({ at: FRIDAY + DAY + 3 * MINUTE, author: "deploy" }, allow("deploy", "*"), [
        "last-manager",
      ]),
      place({ at: FRIDAY + DAY + 4 * MINUTE, author: "ana" }, allow("ana", "*"), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      genesis(FRIDAY + DAY + 4 * MINUTE, allow("ana", "*"), ["not-first"]),
    ],
  },
  {
    id: "authority/permanent/held-through-a-group",
    title: "A platform admins group holds the root: members act as permanent managers",
    proves: ["A7", "D9", "A3"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("platform-admins", "*")),
      ask(
        { at: MONDAY + MINUTE, subject: "ann", groups: ["platform-admins"], place: ACME },
        "org:own",
        "allowed",
      ),
      place(
        { at: MONDAY + 2 * MINUTE, author: "ann", groups: ["platform-admins"] },
        allow("bo", "report:read", { place: ACME }),
      ),
      place(
        { at: MONDAY + 3 * MINUTE, author: "ann", groups: ["platform-admins"] },
        allow("ann", "report:read", { place: ACME }),
        ["about-self"],
      ),
      place(
        { at: MONDAY + 4 * MINUTE, author: "ann", groups: ["platform-admins"] },
        deny("platform-admins", "report:read", { place: ACME }),
      ),
      ask(
        { at: MONDAY + 5 * MINUTE, subject: "ann", groups: ["platform-admins"], place: ACME },
        "report:read",
        "allowed",
      ),
      remove(
        { at: MONDAY + 6 * MINUTE, author: "ann", groups: ["platform-admins"] },
        allow("platform-admins", "*"),
        ["last-manager"],
      ),
      place(
        { at: MONDAY + 7 * MINUTE, author: "ann", groups: ["platform-admins"] },
        allow("platform-admins", "*", { until: MONDAY + 30 * DAY }),
        ["last-manager"],
      ),
      place(
        { at: MONDAY + 8 * MINUTE, author: "ann", groups: ["platform-admins"] },
        allow("deploy", "*"),
      ),
      remove(
        { at: MONDAY + 9 * MINUTE, author: "ann", groups: ["platform-admins"] },
        allow("platform-admins", "*"),
      ),
      ask(
        { at: MONDAY + 10 * MINUTE, subject: "ann", groups: ["platform-admins"], place: ACME },
        "org:own",
        "denied",
      ),
    ],
  },
  {
    id: "authority/permanent/restrictions-wait-until-the-subject-is-no-longer-one",
    title:
      "A deny and an exclusion placed on root managers stay silent, and the deny bites once the owner steps down",
    proves: ["D9"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("deploy", "*")),
      place({ at: MONDAY + 2 * MINUTE, author: "owner" }, allow("tom", "*", { place: ACME })),
      place(
        { at: MONDAY + 3 * MINUTE, author: "tom" },
        deny("owner", "report:read", { place: ACME }),
      ),
      place(
        { at: MONDAY + 4 * MINUTE, author: "tom" },
        exclude("deploy", "audit-log:read", { place: ACME }),
      ),
      ask({ at: MONDAY + 5 * MINUTE, subject: "owner", place: ACME }, "report:read", "allowed"),
      ask({ at: MONDAY + 5 * MINUTE, subject: "deploy", place: ACME }, "audit-log:read", "allowed"),
      place(
        { at: MONDAY + 6 * MINUTE, author: "owner" },
        allow("ike", "report:read", { place: ARCHIVES }),
      ),
      place(
        { at: MONDAY + 7 * MINUTE, author: "deploy" },
        allow("owner", "report:read", { place: ACME }),
      ),
      remove({ at: MONDAY + 8 * MINUTE, author: "deploy" }, allow("owner", "*")),
      ask({ at: MONDAY + 9 * MINUTE, subject: "owner", place: ACME }, "report:read", "denied"),
      remove(
        { at: MONDAY + 10 * MINUTE, author: "tom" },
        deny("owner", "report:read", { place: ACME }),
      ),
      ask({ at: MONDAY + 11 * MINUTE, subject: "owner", place: ACME }, "report:read", "allowed"),
    ],
  },
  {
    id: "authority/permanent/root-management-survives-everything",
    title: "Denied, excluded and decades later, the root service still holds every permission",
    proves: ["G3"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("root-svc", "*")),
      place({ at: MONDAY + MINUTE, author: "root-svc" }, assign("vic", "owner")),
      place({ at: MONDAY + 2 * MINUTE, author: "vic" }, deny("root-svc", "*")),
      place({ at: MONDAY + 3 * MINUTE, author: "vic" }, exclude("root-svc", "*", { place: ACME })),
      ask({ at: YEAR_2100, subject: "root-svc", place: ACME }, "report:delete", "allowed"),
      ask({ at: YEAR_2100, subject: "root-svc" }, "access:manage", "allowed"),
      remove({ at: YEAR_2100, author: "root-svc" }, allow("root-svc", "*"), ["last-manager"]),
      remove({ at: YEAR_2100, author: "root-svc" }, deny("root-svc", "*"), ["about-self"]),
      remove({ at: YEAR_2100 + MINUTE, author: "root-svc" }, assign("vic", "owner")),
      ask({ at: YEAR_2100 + 2 * MINUTE, subject: "vic", place: ACME }, "org:own", "denied"),
    ],
  },
  {
    id: "authority/permanent/free-of-denies-under-the-place",
    title:
      "An admin bars the owner from the archives, and the owner still hands out reading of the whole organisation",
    proves: ["D9", "A2"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("tom", "*", { place: ACME })),
      place(
        { at: MONDAY + HOUR, author: "tom" },
        deny("owner", "report:read", { place: ARCHIVES }),
      ),
      place({ at: MONDAY + HOUR, author: "tom" }, deny("dan", "report:read", { place: ARCHIVES })),
      place({ at: MONDAY + 2 * HOUR, author: "owner" }, allow("dan", "*", { place: ACME })),
      place(
        { at: MONDAY + 3 * HOUR, author: "owner" },
        allow("ike", "report:read", { place: ACME }),
      ),
      place(
        { at: MONDAY + 3 * HOUR, author: "dan" },
        allow("eli", "report:read", { place: ACME }),
        ["not-held"],
      ),
      ask({ at: MONDAY + 4 * HOUR, subject: "ike", place: ARCHIVES }, "report:read", "allowed"),
      ask({ at: MONDAY + 4 * HOUR, subject: "owner", place: ARCHIVES }, "report:read", "allowed"),
    ],
  },
  {
    id: "authority/permanent/undoes-what-any-manager-did",
    title: "The owner clears everything an organisation admin wrote, except the deny about herself",
    proves: ["G4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("tom", "*", { place: ACME })),
      place(
        { at: MONDAY + 2 * MINUTE, author: "tom", groups: ["acme-members"] },
        deny("acme-members", "report:write", { place: ACME }),
      ),
      place(
        { at: MONDAY + 3 * MINUTE, author: "tom", groups: ["acme-members"] },
        exclude("ike", "report:read", { place: ARCHIVES }),
      ),
      place(
        { at: MONDAY + 4 * MINUTE, author: "tom", groups: ["acme-members"] },
        deny("owner", "audit-log:read", { place: ACME }),
      ),
      place(
        { at: MONDAY + 5 * MINUTE, author: "tom", groups: ["acme-members"] },
        allow("ike", "vm:start", { place: ACME }),
      ),
      remove(
        { at: MONDAY + 6 * MINUTE, author: "tom", groups: ["acme-members"] },
        deny("acme-members", "report:write", { place: ACME }),
        ["not-held"],
      ),
      remove(
        { at: MONDAY + 7 * MINUTE, author: "owner" },
        deny("acme-members", "report:write", { place: ACME }),
      ),
      remove(
        { at: MONDAY + 7 * MINUTE, author: "owner" },
        exclude("ike", "report:read", { place: ARCHIVES }),
      ),
      remove(
        { at: MONDAY + 7 * MINUTE, author: "owner" },
        allow("ike", "vm:start", { place: ACME }),
      ),
      remove({ at: MONDAY + 7 * MINUTE, author: "owner" }, allow("tom", "*", { place: ACME })),
      remove(
        { at: MONDAY + 8 * MINUTE, author: "owner" },
        deny("owner", "audit-log:read", { place: ACME }),
        ["about-self"],
      ),
      ask({ at: MONDAY + 9 * MINUTE, subject: "owner", place: ACME }, "audit-log:read", "allowed"),
      ask({ at: MONDAY + 9 * MINUTE, subject: "ike", place: ACME }, "vm:start", "denied"),
      ask({ at: MONDAY + 9 * MINUTE, subject: "tom", place: ACME }, "report:read", "denied"),
    ],
  },
  {
    id: "authority/self/only-genesis-is-about-oneself",
    title: "The founder writes about herself once, at genesis, and never again",
    proves: ["G2"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("ana", "*")),
      place({ at: MONDAY + MINUTE, author: "ana" }, allow("ana", "report:read", { place: ACME }), [
        "about-self",
      ]),
      place({ at: MONDAY + 2 * MINUTE, author: "ana" }, deny("ana", "audit-log:delete"), [
        "about-self",
      ]),
      place(
        { at: MONDAY + 3 * MINUTE, author: "ana" },
        exclude("ana", "report:write", { place: ARCHIVES }),
        ["about-self"],
      ),
      place({ at: MONDAY + 4 * MINUTE, author: "ana" }, assign("ana", "viewer", { place: ACME }), [
        "about-self",
      ]),
      place({ at: MONDAY + 5 * MINUTE, author: "ana" }, allow("ana", "*"), ["about-self"]),
      genesis(MONDAY + 5 * MINUTE, allow("ana", "*"), ["not-first"]),
      place(
        { at: MONDAY + 6 * MINUTE, author: "ana", groups: ["acme-admins"] },
        allow("acme-admins", "report:read", { place: ACME }),
      ),
      ask(
        { at: MONDAY + 7 * MINUTE, subject: "bea", groups: ["acme-admins"], place: ACME },
        "report:read",
        "allowed",
      ),
    ],
  },
];
