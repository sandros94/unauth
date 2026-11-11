import type { Scenario } from "../types.ts";
import {
  ACME,
  ARCHIVES,
  CLOUD,
  CORE,
  DAY,
  DEC_1,
  FRIDAY,
  HOUR,
  MINUTE,
  MONDAY,
  OPS,
  P1,
  SALES,
  WORKSPACE,
  allow,
  ask,
  assign,
  deny,
  exclude,
  genesis,
  place,
  remove,
} from "./_internal/authority.ts";

export const authorityHoldingScenarios: readonly Scenario[] = [
  {
    id: "authority/hold/hand-out-only-what-you-hold",
    title: "An organisation manager who writes reports hands out reading and writing, nothing more",
    proves: ["A2", "G1"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("lena", "access:manage", { place: ACME }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("lena", "report:write", { place: ACME }),
      ),
      place({ at: MONDAY + HOUR, author: "lena" }, allow("ike", "report:read", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "lena" }, allow("ike", "report:write", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "lena" }, allow("ike", "report:*", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "lena" }, assign("ike", "viewer", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "lena" }, assign("ike", "support", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "lena" }, deny("ike", "report:delete", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "lena" }, deny("ike", "report:write", { place: SALES })),
      ask({ at: MONDAY + 2 * HOUR, subject: "ike", place: SALES }, "report:write", "denied"),
      ask({ at: MONDAY + 2 * HOUR, subject: "ike", place: SALES }, "report:read", "allowed"),
      ask({ at: MONDAY + 2 * HOUR, subject: "ike", place: ACME }, "report:delete", "denied"),
      ask({ at: MONDAY + 2 * HOUR, subject: "ike", place: ACME }, "audit-log:read", "denied"),
    ],
  },
  {
    id: "authority/hold/a-restriction-needs-what-it-names",
    title: "A deny of a wildcard asks for every permission it reaches",
    proves: ["A2"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("bo", "access:manage", { place: ACME }),
      ),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("bo", "report:read", { place: ACME })),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("kim", "*", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "bo" }, deny("kim", "*", { place: ACME }), ["not-held"]),
      place({ at: MONDAY + HOUR, author: "bo" }, deny("kim", "*:read", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "bo" }, exclude("kim", "report:*", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "bo" }, deny("kim", "report:read", { place: ACME })),
      ask({ at: MONDAY + 2 * HOUR, subject: "kim", place: ACME }, "report:write", "denied"),
      ask({ at: MONDAY + 2 * HOUR, subject: "kim", place: ACME }, "audit-log:read", "allowed"),
      place({ at: MONDAY + 3 * HOUR, author: "owner" }, deny("kim", "*", { place: ACME })),
      ask({ at: MONDAY + 4 * HOUR, subject: "kim", place: ACME }, "audit-log:read", "denied"),
    ],
  },
  {
    id: "authority/hold/no-longer-than-you-hold",
    title:
      "A contractor manager hands out access within his own contract, while his restrictions outlive it",
    proves: ["A2", "A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("cal", "access:manage", { place: ACME }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("cal", "report:write", { place: ACME, until: FRIDAY }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        assign("cal", "editor", { place: ACME, until: DEC_1 }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("ike", "report:write", { place: ACME }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        assign("contractors", "editor", { place: ACME }),
      ),
      place(
        { at: MONDAY + HOUR, author: "cal" },
        allow("dana", "report:write", { place: ACME, until: DEC_1 }),
      ),
      place(
        { at: MONDAY + HOUR, author: "cal" },
        allow("dana", "report:write", { place: P1, until: DEC_1 + DAY }),
        ["not-held"],
      ),
      place({ at: MONDAY + HOUR, author: "cal" }, allow("eli", "report:write", { place: ACME }), [
        "not-held",
      ]),
      place(
        { at: MONDAY + HOUR, author: "cal" },
        allow("eli", "vm:start", { place: ACME, until: DEC_1 }),
      ),
      place({ at: MONDAY + HOUR, author: "cal" }, deny("spam", "report:write", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "cal" }, exclude("spam", "vm:start", { place: ACME })),
      remove(
        { at: MONDAY + 2 * HOUR, author: "cal" },
        allow("ike", "report:write", { place: ACME }),
      ),
      place(
        { at: MONDAY + 3 * HOUR, author: "cal" },
        allow("ike", "report:write", { place: ACME }),
        ["not-held"],
      ),
      ask({ at: FRIDAY + HOUR, subject: "dana", place: ACME }, "report:write", "allowed"),
      ask({ at: FRIDAY + HOUR, subject: "cal", place: ACME }, "report:write", "allowed"),
      ask({ at: DEC_1, subject: "dana", place: ACME }, "report:write", "denied"),
      ask({ at: DEC_1, subject: "eli", place: ACME }, "vm:start", "denied"),
      ask(
        { at: DEC_1 + DAY, subject: "spam", groups: ["contractors"], place: ACME },
        "report:write",
        "denied",
      ),
      ask(
        { at: DEC_1 + DAY, subject: "spam", groups: ["contractors"], place: ACME },
        "vm:start",
        "denied",
      ),
      ask(
        { at: DEC_1 + DAY, subject: "carl", groups: ["contractors"], place: ACME },
        "vm:start",
        "allowed",
      ),
    ],
  },
  {
    id: "authority/hold/denied-under-the-place",
    title:
      "Dan runs acme but is kept out of its archives: he cannot hand reading of the whole organisation around that",
    proves: ["A2", "A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("dan", "*", { place: ACME })),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        deny("dan", "report:read", { place: ARCHIVES }),
      ),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("jo", "report:read", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "dan" }, allow("ike", "report:read", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "dan" }, allow("ike", "report:write", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "dan" }, assign("ike", "support", { place: ACME }), [
        "not-held",
      ]),
      place({ at: MONDAY + HOUR, author: "dan" }, allow("ike", "report:read", { place: SALES })),
      place({ at: MONDAY + HOUR, author: "dan" }, allow("ike", "vm:start", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "dan" }, deny("eve", "report:read", { place: ACME })),
      remove({ at: MONDAY + HOUR, author: "dan" }, allow("jo", "report:read", { place: ACME })),
      ask({ at: MONDAY + 2 * HOUR, subject: "jo", place: ACME }, "report:read", "denied"),
      remove(
        { at: MONDAY + 3 * HOUR, author: "owner" },
        deny("dan", "report:read", { place: ARCHIVES }),
      ),
      place(
        { at: MONDAY + 3 * HOUR, author: "owner" },
        exclude("dan", "report:read", { place: ARCHIVES }),
      ),
      place({ at: MONDAY + 4 * HOUR, author: "dan" }, allow("ike", "report:read", { place: ACME })),
      ask({ at: MONDAY + 5 * HOUR, subject: "ike", place: ARCHIVES }, "report:read", "allowed"),
      ask({ at: MONDAY + 5 * HOUR, subject: "dan", place: ARCHIVES }, "report:read", "denied"),
    ],
  },
  {
    id: "authority/hold/a-deny-on-the-group-under-the-place",
    title:
      "A contractors' freeze on one project blocks their admin's grants over it until it lapses",
    proves: ["A2"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        deny("contractors", "vm:start", { place: P1, until: FRIDAY }),
      ),
      place(
        { at: MONDAY + HOUR, author: "ola", groups: ["contractors"] },
        allow("ike", "vm:start", { place: ACME }),
        ["not-held"],
      ),
      place(
        { at: MONDAY + HOUR, author: "ola", groups: ["contractors"] },
        allow("ike", "vm:start", { place: SALES }),
      ),
      place(
        { at: FRIDAY, author: "ola", groups: ["contractors"] },
        allow("ike", "vm:start", { place: ACME }),
      ),
      ask({ at: FRIDAY + HOUR, subject: "ike", place: P1 }, "vm:start", "allowed"),
    ],
  },
  {
    id: "authority/assigner/adds-members-without-reading",
    title: "A user manager adds members to a team without reading what they read",
    proves: ["A2", "G1", "A3"],
    catalog: WORKSPACE,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("hr", "access:manage", { place: CORE }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("hr", "member:assign", { place: CORE, until: DEC_1 }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("rex", "member:assign", { place: CORE }),
      ),
      place(
        { at: MONDAY + HOUR, author: "hr" },
        assign("nia", "member", { place: CORE, until: DEC_1 }),
      ),
      ask({ at: MONDAY + 2 * HOUR, subject: "nia", place: CORE }, "doc:write", "allowed"),
      ask({ at: MONDAY + 2 * HOUR, subject: "hr", place: CORE }, "doc:read", "denied"),
      place({ at: MONDAY + 3 * HOUR, author: "hr" }, assign("omar", "member", { place: CORE }), [
        "not-held",
      ]),
      place(
        { at: MONDAY + 3 * HOUR, author: "hr" },
        assign("omar", "auditor", { place: CORE, until: DEC_1 }),
        ["not-held"],
      ),
      place({ at: MONDAY + 3 * HOUR, author: "hr" }, allow("omar", "doc:write", { place: CORE }), [
        "not-held",
      ]),
      place(
        { at: MONDAY + 3 * HOUR, author: "hr" },
        assign("hr", "member", { place: CORE, until: DEC_1 }),
        ["about-self"],
      ),
      place(
        { at: MONDAY + 3 * HOUR, author: "hr" },
        assign("omar", "member", { place: OPS, until: DEC_1 }),
        ["not-manager", "not-held"],
      ),
      place(
        { at: MONDAY + 3 * HOUR, author: "rex" },
        assign("omar", "member", { place: CORE, until: DEC_1 }),
        ["not-manager"],
      ),
      remove({ at: MONDAY + 4 * HOUR, author: "hr" }, assign("nia", "member", { place: CORE })),
      ask({ at: MONDAY + 5 * HOUR, subject: "nia", place: CORE }, "doc:write", "denied"),
    ],
  },
];
