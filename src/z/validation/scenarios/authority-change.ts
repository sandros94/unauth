import type { Scenario } from "../types.ts";
import {
  ACME,
  CLOUD,
  DAY,
  DEC_1,
  FRIDAY,
  GLOBEX,
  HOUR,
  HR,
  MINUTE,
  MONDAY,
  P1,
  SALES,
  allow,
  ask,
  deny,
  genesis,
  place,
  remove,
} from "./_internal/authority.ts";

export const authorityChangeScenarios: readonly Scenario[] = [
  {
    id: "authority/manage/management-that-ends",
    title: "A temporary manager's own reading is permanent, so what he gives may be too",
    proves: ["A1"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("tess", "access:manage", { place: ACME, until: FRIDAY }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("tess", "report:read", { place: ACME }),
      ),
      place({ at: MONDAY + HOUR, author: "tess" }, allow("ike", "report:read", { place: ACME })),
      place({ at: FRIDAY, author: "tess" }, allow("ike", "report:read", { place: SALES }), [
        "not-manager",
      ]),
      remove({ at: FRIDAY, author: "tess" }, allow("ike", "report:read", { place: ACME }), [
        "not-manager",
      ]),
      ask({ at: FRIDAY + DAY, subject: "ike", place: ACME }, "report:read", "allowed"),
    ],
  },
  {
    id: "authority/manage/only-where-you-manage",
    title: "A reader of everything who manages one organisation changes nothing outside it",
    proves: ["A1"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("ola", "access:manage", { place: ACME }),
      ),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "report:read")),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("ike", "report:read", { place: ACME })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("ike", "report:read", { place: SALES })),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("ike", "report:read", { place: GLOBEX }), [
        "not-manager",
      ]),
      place({ at: MONDAY + HOUR, author: "ola" }, allow("ike", "report:read"), ["not-manager"]),
      ask({ at: MONDAY + 2 * HOUR, subject: "ike", place: GLOBEX }, "report:read", "denied"),
      place(
        { at: MONDAY + 3 * HOUR, author: "owner" },
        deny("ola", "access:manage", { place: HR }),
      ),
      place({ at: MONDAY + 4 * HOUR, author: "ola" }, allow("ike", "report:read", { place: HR }), [
        "not-manager",
      ]),
      place(
        { at: MONDAY + 5 * HOUR, author: "owner" },
        allow("acme-leads", "org:own", { place: ACME }),
      ),
      place(
        { at: MONDAY + 6 * HOUR, author: "lin", groups: ["acme-leads"] },
        allow("ike", "access:manage", { place: SALES }),
      ),
      place(
        { at: MONDAY + 6 * HOUR, author: "lin" },
        allow("ike", "access:manage", { place: P1 }),
        ["not-manager", "not-held"],
      ),
      ask({ at: MONDAY + 7 * HOUR, subject: "ike", place: SALES }, "access:manage", "allowed"),
      ask({ at: MONDAY + 7 * HOUR, subject: "ike", place: P1 }, "access:manage", "denied"),
    ],
  },
  {
    id: "authority/identity/one-statement-per-identity",
    title: "An access is extended, shortened and lapses, one statement throughout",
    proves: ["A2", "A4"],
    catalog: CLOUD,
    steps: [
      genesis(MONDAY, allow("owner", "*")),
      place({ at: MONDAY + MINUTE, author: "owner" }, allow("ola", "*", { place: ACME })),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("cal", "access:manage", { place: ACME }),
      ),
      place(
        { at: MONDAY + MINUTE, author: "owner" },
        allow("cal", "report:read", { place: ACME, until: FRIDAY }),
      ),
      place(
        { at: MONDAY + HOUR, author: "cal" },
        allow("dana", "report:read", { place: ACME, until: FRIDAY }),
      ),
      place(
        { at: MONDAY + 2 * HOUR, author: "cal" },
        allow("dana", "report:read", { place: ACME, until: DEC_1 }),
        ["not-held"],
      ),
      place(
        { at: MONDAY + 3 * HOUR, author: "ola" },
        allow("dana", "report:read", { place: ACME, until: DEC_1 }),
      ),
      ask({ at: FRIDAY + DAY, subject: "dana", place: ACME }, "report:read", "allowed"),
      remove({ at: FRIDAY + DAY, author: "ola" }, deny("dana", "report:read", { place: ACME })),
      ask({ at: FRIDAY + DAY + MINUTE, subject: "dana", place: ACME }, "report:read", "allowed"),
      remove(
        { at: FRIDAY + DAY + MINUTE, author: "eli" },
        deny("dana", "report:read", { place: ACME }),
        ["not-manager", "not-held"],
      ),
      place(
        { at: FRIDAY + DAY + HOUR, author: "ola" },
        allow("dana", "report:read", { place: ACME, until: FRIDAY + 3 * DAY }),
      ),
      ask({ at: FRIDAY + 3 * DAY, subject: "dana", place: ACME }, "report:read", "denied"),
      place(
        { at: FRIDAY + 3 * DAY, author: "ola" },
        allow("dana", "report:read", { place: SALES, until: FRIDAY + 3 * DAY }),
        ["ended"],
      ),
      place(
        { at: FRIDAY + 3 * DAY, author: "ola" },
        allow("dana", "report:read", { place: SALES, until: MONDAY }),
        ["ended"],
      ),
      ask({ at: FRIDAY + 3 * DAY, subject: "dana", place: SALES }, "report:read", "denied"),
    ],
  },
];
