import type { Scenario } from "../types.ts";
import {
  ACME,
  ARCHIVES,
  CLOUD,
  DEC_1,
  FRIDAY,
  HOUR,
  MINUTE,
  MONDAY,
  P1,
  WEB,
  allow,
  ask,
  assign,
  deny,
  exclude,
  genesis,
  place,
  remove,
} from "./_internal/authority.ts";

export const authorityScenarios: readonly Scenario[] = [
  {
    id: "authority/self/never-for-yourself",
    title: "An organisation admin may drop her own access but never write or lift her own",
    proves: ["A3"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        deny("ola", "audit-log:delete", { place: ACME }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        exclude("ola", "report:write", { place: ARCHIVES }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        assign("lea", "editor", { place: P1, until: DEC_1 }),
      ),
      place(
        { at: MONDAY + HOUR, author: "ola", groups: ["acme-admins"] },
        allow("ola", "vm:start", { place: P1 }),
        ["about-self"],
      ),
      place(
        { at: MONDAY + HOUR, author: "ola", groups: ["acme-admins"] },
        deny("ola", "report:read", { place: P1 }),
        ["about-self"],
      ),
      remove(
        { at: MONDAY + HOUR, author: "ola", groups: ["acme-admins"] },
        deny("ola", "audit-log:delete", { place: ACME }),
        ["about-self", "not-held"],
      ),
      remove(
        { at: MONDAY + HOUR, author: "ola", groups: ["acme-admins"] },
        exclude("ola", "report:write", { place: ARCHIVES }),
        ["about-self", "not-held"],
      ),
      place(
        { at: MONDAY + HOUR, author: "ola", groups: ["acme-admins"] },
        allow("acme-admins", "vm:start", { place: ACME }),
      ),
      remove({ at: MONDAY + 2 * HOUR, author: "lea" }, assign("lea", "editor", { place: P1 })),
      ask({ at: MONDAY + 3 * HOUR, subject: "lea", place: P1 }, "vm:start", "denied"),
      remove(
        { at: MONDAY + 3 * HOUR, author: "ola", groups: ["acme-admins"] },
        allow("ola", "*", { place: ACME }),
      ),
      ask(
        { at: MONDAY + 4 * HOUR, subject: "ola", groups: ["acme-admins"], place: P1 },
        "vm:start",
        "allowed",
      ),
      ask(
        { at: MONDAY + 4 * HOUR, subject: "ola", groups: ["acme-admins"], place: ACME },
        "report:read",
        "denied",
      ),
    ],
  },
  {
    id: "authority/remove/only-what-you-could-give",
    title:
      "A project lead lifts what she could have placed, and nothing her organisation admin holds above her",
    proves: ["A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("pia", "access:manage", { place: WEB })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("pia", "report:write", { place: WEB })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("kim", "vm:start", { place: WEB })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("kim", "report:write", { place: WEB })),
      place({ at: MONDAY + HOUR, author: "ola" }, deny("kim", "report:write", { place: WEB })),
      remove({ at: MONDAY + 2 * HOUR, author: "pia" }, allow("ola", "*", { place: ACME }), [
        "not-manager",
        "not-held",
      ]),
      remove({ at: MONDAY + 2 * HOUR, author: "pia" }, allow("kim", "vm:start", { place: WEB }), [
        "not-held",
      ]),
      ask({ at: MONDAY + 2 * HOUR, subject: "kim", place: WEB }, "report:write", "denied"),
      remove({ at: MONDAY + 3 * HOUR, author: "pia" }, deny("kim", "report:write", { place: WEB })),
      ask({ at: MONDAY + 3 * HOUR, subject: "kim", place: WEB }, "report:write", "allowed"),
      place({ at: MONDAY + 4 * HOUR, author: "ola" }, deny("kim", "report:write", { place: ACME })),
      remove(
        { at: MONDAY + 5 * HOUR, author: "pia" },
        deny("kim", "report:write", { place: ACME }),
        ["not-manager", "not-held"],
      ),
      ask({ at: MONDAY + 5 * HOUR, subject: "kim", place: WEB }, "report:write", "denied"),
      remove(
        { at: MONDAY + 6 * HOUR, author: "ola" },
        allow("pia", "access:manage", { place: WEB }),
      ),
      remove(
        { at: MONDAY + 7 * HOUR, author: "pia" },
        allow("kim", "report:write", { place: WEB }),
        ["not-manager"],
      ),
    ],
  },
  {
    id: "authority/restrict/a-manager-restricts-a-wider-one",
    title:
      "A project lead denies her organisation admin inside the project, and only someone above them both lifts it",
    proves: ["A3", "A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("pia", "*", { place: WEB })),
      place({ at: MONDAY + 2 * HOUR, author: "pia" }, deny("ola", "report:read", { place: WEB })),
      ask({ at: MONDAY + 3 * HOUR, subject: "ola", place: WEB }, "report:read", "denied"),
      ask({ at: MONDAY + 3 * HOUR, subject: "ola", place: ACME }, "report:read", "allowed"),
      remove({ at: MONDAY + 3 * HOUR, author: "ola" }, deny("ola", "report:read", { place: WEB }), [
        "about-self",
        "not-held",
      ]),
      remove({ at: MONDAY + 3 * HOUR, author: "ola" }, allow("pia", "*", { place: WEB }), [
        "not-held",
      ]),
      remove(
        { at: MONDAY + 4 * HOUR, author: "owner" },
        deny("ola", "report:read", { place: WEB }),
      ),
      ask({ at: MONDAY + 5 * HOUR, subject: "ola", place: WEB }, "report:read", "allowed"),
      remove({ at: MONDAY + 5 * HOUR, author: "ola" }, allow("pia", "*", { place: WEB })),
      ask({ at: MONDAY + 6 * HOUR, subject: "pia", place: WEB }, "report:read", "denied"),
    ],
  },
  {
    id: "authority/restrict/a-manager-restricts-their-own-group",
    title:
      "A project lead freezes writing for her own team, herself included, and must ask above to lift it",
    proves: ["A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("pia", "*", { place: WEB })),
      place(
        { at: MONDAY + 2 * HOUR, author: "pia", groups: ["web-team"] },
        deny("web-team", "report:write", { place: WEB }),
      ),
      ask(
        { at: MONDAY + 3 * HOUR, subject: "pia", groups: ["web-team"], place: WEB },
        "report:write",
        "denied",
      ),
      ask(
        { at: MONDAY + 3 * HOUR, subject: "pia", groups: ["web-team"], place: WEB },
        "report:read",
        "allowed",
      ),
      remove(
        { at: MONDAY + 3 * HOUR, author: "pia", groups: ["web-team"] },
        deny("web-team", "report:write", { place: WEB }),
        ["not-held"],
      ),
      remove(
        { at: MONDAY + 4 * HOUR, author: "ola" },
        deny("web-team", "report:write", { place: WEB }),
      ),
      ask(
        { at: MONDAY + 5 * HOUR, subject: "pia", groups: ["web-team"], place: WEB },
        "report:write",
        "allowed",
      ),
    ],
  },
  {
    id: "authority/reasons/every-reason-named",
    title: "Changes that break several rules at once name every rule they break",
    proves: ["A1", "A2", "A3", "A4", "A7"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("tom", "*", { place: ACME })),
      place({ at: MONDAY + MINUTE, author: "owner" }, deny("zed", "report:read", { place: ACME })),
      remove({ at: MONDAY + HOUR, author: "tom" }, allow("owner", "*"), [
        "not-manager",
        "not-held",
        "last-manager",
      ]),
      remove({ at: MONDAY + HOUR, author: "zed" }, deny("zed", "report:read", { place: ACME }), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      place({ at: MONDAY + HOUR, author: "owner" }, allow("owner", "*", { until: FRIDAY }), [
        "about-self",
        "last-manager",
      ]),
      place(
        { at: MONDAY + HOUR, author: "zed" },
        allow("zed", "report:read", { place: ACME, until: MONDAY }),
        ["not-manager", "not-held", "about-self", "ended"],
      ),
      ask({ at: FRIDAY + HOUR, subject: "owner", place: ACME }, "report:read", "allowed"),
    ],
  },
  {
    id: "authority/input/refused-before-any-rule",
    title: "A stranger's malformed changes are refused for their form before any rule of authority",
    proves: [],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        allow("ike", "invoice:read", { place: ACME }),
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        allow("ike", "invoice:*", { place: ACME }),
        "ERR_AUTHZ_PERMISSION_UNKNOWN",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        allow("ike", "Report:read", { place: ACME }),
        "ERR_AUTHZ_MALFORMED",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        deny("ike", "*:*", { place: ACME }),
        "ERR_AUTHZ_MALFORMED",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        allow("ike", "report:read", { place: "/org=acme/" }),
        "ERR_AUTHZ_MALFORMED",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        allow("ike", "report:read", { place: "/project=p1" }),
        "ERR_AUTHZ_PLACE_OUTSIDE",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        allow("ike", "report:read", { place: ACME, until: FRIDAY * 1000 }),
        "ERR_AUTHZ_MALFORMED",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        allow("ike", "report:read", { place: ACME, until: FRIDAY + 0.5 }),
        "ERR_AUTHZ_MALFORMED",
      ),
      place(
        { at: MONDAY + MINUTE, author: "eve" },
        assign("ike", "ghost", { place: ACME }),
        "ERR_AUTHZ_ROLE_INVALID",
      ),
      place({ at: MONDAY + MINUTE, author: "eve" }, allow("ike", "report:read", { place: ACME }), [
        "not-manager",
        "not-held",
      ]),
      place(
        { at: MONDAY + 2 * MINUTE, author: "owner" },
        allow("ike", "report:read", { place: ACME, until: FRIDAY * 1000 }),
        "ERR_AUTHZ_MALFORMED",
      ),
      ask({ at: MONDAY + 3 * MINUTE, subject: "ike", place: ACME }, "report:read", "denied"),
    ],
  },
];
