import type { Scenario } from "../types.ts";
import {
  ACME,
  BLOG,
  BLOG_UNMANAGED,
  CLOUD,
  DAY,
  HOUR,
  MINUTE,
  MONDAY,
  TENANTS,
  allow,
  ask,
  genesis,
  place,
} from "./_internal/authority.ts";

export const authorityGenesisScenarios: readonly Scenario[] = [
  {
    id: "authority/genesis/first-sign-in-takes-the-root",
    title: "The first person to sign in becomes the root manager, and the door closes behind him",
    proves: ["A5"],
    catalog: BLOG,
    steps: [
      ask({ at: MONDAY, subject: "ed" }, "post:read", "denied"),
      place({ at: MONDAY, author: "ed" }, allow("ed", "*"), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      genesis(MONDAY, allow("ed", "*")),
      ask({ at: MONDAY + MINUTE, subject: "ed" }, "post:publish", "allowed"),
      genesis(MONDAY + HOUR, allow("mallory", "*"), ["not-first"]),
      place({ at: MONDAY + HOUR, author: "mallory" }, allow("mallory", "*"), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      place({ at: MONDAY + HOUR, author: "mallory" }, allow("eve", "*"), [
        "not-manager",
        "not-held",
      ]),
      ask({ at: MONDAY + HOUR, subject: "mallory" }, "post:read", "denied"),
      ask({ at: MONDAY + HOUR, subject: "eve" }, "post:read", "denied"),
    ],
  },
  {
    id: "authority/genesis/installer-names-the-deploy-job",
    title: "An installer performs genesis for the deploy job and keeps nothing for itself",
    proves: ["A5"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("deploy", "*")),
      ask({ at: MONDAY + MINUTE, subject: "installer", place: ACME }, "report:read", "denied"),
      ask({ at: MONDAY + MINUTE, subject: "deploy", place: ACME }, "report:read", "allowed"),
      genesis(MONDAY + 2 * MINUTE, allow("installer", "*"), ["not-first"]),
      place({ at: MONDAY + 2 * MINUTE, author: "installer" }, allow("installer", "*"), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      place({ at: MONDAY + 3 * MINUTE, author: "deploy" }, allow("tom", "*", { place: ACME })),
      ask({ at: MONDAY + 4 * MINUTE, subject: "tom", place: ACME }, "org:own", "allowed"),
    ],
  },
  {
    id: "authority/genesis/open-until-the-root-holds-a-permanent-management",
    title:
      "A seeded deployment with a temporary root allow and an organisation owner still has genesis open",
    proves: ["A5", "A2"],
    catalog: CLOUD,
    statements: [
      allow("ops", "*", { until: MONDAY + DAY }),
      allow("acme-admin", "*", { place: ACME }),
    ],
    steps: [
      place({ at: MONDAY, author: "kai" }, allow("svc", "*", { until: MONDAY + 7 * DAY }), [
        "not-manager",
        "not-held",
      ]),
      genesis(MONDAY, allow("svc", "*", { until: MONDAY + 7 * DAY }), "ERR_AUTHZ_MALFORMED"),
      genesis(MONDAY + MINUTE, allow("svc", "*")),
      ask({ at: MONDAY + 2 * MINUTE, subject: "svc", place: ACME }, "vm:start", "allowed"),
      genesis(MONDAY + 3 * MINUTE, allow("kai", "*"), ["not-first"]),
      place({ at: MONDAY + 3 * MINUTE, author: "kai" }, allow("kai", "*"), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      place({ at: MONDAY + 4 * MINUTE, author: "ops" }, allow("ops-2", "*"), ["not-held"]),
      place({ at: MONDAY + 5 * MINUTE, author: "acme-admin" }, allow("ops-2", "*"), [
        "not-manager",
        "not-held",
      ]),
    ],
  },
  {
    id: "authority/genesis/an-ordinary-change-never-opens-the-root",
    title:
      "With no permanent manager stored, no ordinary change places one, whoever asks and whatever they hold",
    proves: ["A5", "A2"],
    catalog: CLOUD,
    statements: [
      allow("ops", "*", { until: MONDAY + DAY }),
      allow("acme-admin", "*", { place: ACME }),
    ],
    steps: [
      place({ at: MONDAY, author: "kai" }, allow("kai", "*"), [
        "not-manager",
        "not-held",
        "about-self",
      ]),
      place({ at: MONDAY, author: "kai" }, allow("svc", "*"), ["not-manager", "not-held"]),
      place({ at: MONDAY, author: "ops" }, allow("svc", "*"), ["not-held"]),
      place({ at: MONDAY, author: "ops" }, allow("ops", "*"), ["not-held", "about-self"]),
      place({ at: MONDAY, author: "acme-admin" }, allow("svc", "*"), ["not-manager", "not-held"]),
      ask({ at: MONDAY + MINUTE, subject: "svc", place: ACME }, "vm:start", "denied"),
      genesis(MONDAY + 2 * MINUTE, allow("svc", "*")),
      ask({ at: MONDAY + 3 * MINUTE, subject: "svc", place: ACME }, "vm:start", "allowed"),
    ],
  },
  {
    id: "authority/genesis/whatever-the-manager-permission-is-called",
    title: "A catalog whose managers hold `tenant:administer` opens with the same genesis",
    proves: ["A5", "A1", "A2"],
    catalog: TENANTS,
    steps: [
      genesis(MONDAY, allow("founder", "*")),
      place(
        { at: MONDAY + MINUTE, author: "founder" },
        allow("tina", "tenant:administer", { place: "/tenant=t1" }),
      ),
      place(
        { at: MONDAY + 2 * MINUTE, author: "tina" },
        allow("uma", "doc:read", { place: "/tenant=t1" }),
        ["not-held"],
      ),
      place(
        { at: MONDAY + 3 * MINUTE, author: "founder" },
        allow("tina", "doc:write", { place: "/tenant=t1" }),
      ),
      place(
        { at: MONDAY + 4 * MINUTE, author: "tina" },
        allow("uma", "doc:read", { place: "/tenant=t1" }),
      ),
      place(
        { at: MONDAY + 5 * MINUTE, author: "tina" },
        allow("uma", "doc:read", { place: "/tenant=t2" }),
        ["not-manager", "not-held"],
      ),
      ask({ at: MONDAY + 6 * MINUTE, subject: "uma", place: "/tenant=t1" }, "doc:read", "allowed"),
      ask({ at: MONDAY + 6 * MINUTE, subject: "uma", place: "/tenant=t2" }, "doc:read", "denied"),
    ],
  },
  {
    id: "authority/genesis/refused-without-a-manager-permission",
    title: "A catalog that designates no manager permission refuses every change, genesis included",
    proves: ["A5"],
    catalog: BLOG_UNMANAGED,
    steps: [
      genesis(MONDAY, allow("ed", "*"), ["not-manager"]),
      ask({ at: MONDAY + MINUTE, subject: "ed" }, "post:read", "denied"),
      { step: "write", save: [allow("ed", "*")] },
      ask({ at: MONDAY + 2 * MINUTE, subject: "ed" }, "post:publish", "allowed"),
      place({ at: MONDAY + 3 * MINUTE, author: "ed" }, allow("assistant", "post:read"), [
        "not-manager",
      ]),
      ask({ at: MONDAY + 4 * MINUTE, subject: "assistant" }, "post:read", "denied"),
      genesis(MONDAY + 5 * MINUTE, allow("bot", "*"), ["not-manager", "not-first"]),
    ],
  },
];
