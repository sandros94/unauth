import type { ExpectedDiverged, GrantsCase } from "../../types.ts";
import {
  ACME,
  DAY,
  FRIDAY_MIDNIGHT,
  LAST_TIME,
  MONDAY,
  readCase,
  reports,
  tabled,
  without,
  zoe,
} from "./_internal/model.ts";

/**
 * Grants that fail a check of form of Section 8.4, asked whether reports are read at the
 * organisation. Validating them whole refuses them all. A read refuses them only where it checks
 * the part that fails (Section 8.3): always for the revision, the fingerprint and the time, which
 * `diverged` reads too, otherwise when the question reads there: the bases, the type of the
 * tables it uses, an entry it looks up and its items, a role name once an entry is found under it,
 * a definition it resolves. `diverged` under the same catalog reads none of those.
 */
export const malformedCases: readonly GrantsCase[] = [
  ...refused(
    [
      ["no-revision", "No format revision", without(zoe, "v")],
      ["revision-as-number", "The format revision written as the number 1", { ...zoe, v: 1 }],
      ["no-fingerprint", "No catalog fingerprint", without(zoe, "ct")],
      ["no-time", "No time of issue", without(zoe, "at")],
      ["time-as-string", "The time of issue written as a string", { ...zoe, at: String(MONDAY) }],
      ["time-fraction", "A time of issue with a fraction", { ...zoe, at: MONDAY + 0.5 }],
      ["time-over-cap", "A time of issue past the year 9999", { ...zoe, at: LAST_TIME + 1 }],
      ["time-negative", "A time of issue before 1970", { ...zoe, at: -1 }],
      ["not-an-object", "A string in place of grants", "grants"],
      ["null", "`null` in place of grants", null],
      [
        "fingerprint-of-one-hash",
        "A fingerprint of 43 characters, one hash of the whole catalog",
        { ...zoe, ct: "tqH3DB6_4qwlAYM-ISbwYLuody-MS18UdumX3CnKB8o" },
      ],
      ["fingerprint-one-segment", "A fingerprint of one segment", { ...zoe, ct: "tqH3DB6_4qw" }],
      [
        "fingerprint-uneven-segments",
        "A fingerprint of 10 and 12 characters",
        { ...zoe, ct: "tqH3DB6_4q.wRBNvo1WzZ4o" },
      ],
      [
        "fingerprint-standard-alphabet",
        "A fingerprint using `+` of the standard base64 alphabet",
        { ...zoe, ct: "tqH3DB6+4qw.RBNvo1WzZ4o" },
      ],
      [
        "fingerprint-padded",
        "A fingerprint with base64 padding",
        { ...zoe, ct: "tqH3DB6_4q=.RBNvo1WzZ4o" },
      ],
      [
        "fingerprint-three-segments",
        "A fingerprint of three segments",
        { ...zoe, ct: "tqH3DB6_4qw.RBNvo1WzZ4o.RBNvo1WzZ4o" },
      ],
      ["fingerprint-as-number", "A fingerprint written as a number", { ...zoe, ct: 1 }],
    ],
    "ERR_AUTHZ_MALFORMED",
  ),
  ...refused(
    [
      ["base-trailing-slash", "A base key ending in `/`", { ...zoe, bs: ["/org=acme/"] }],
      ["base-not-a-key", "A base written without its leading `/`", { ...zoe, bs: ["org=acme"] }],
      ["no-entries", "No entries", without(zoe, "nt")],
      [
        "entries-as-list",
        "Entries written as a list",
        { ...zoe, nt: [["report:*", { a: [[0]] }]] },
      ],
      [
        "stored-role-name-uppercase-assigned",
        "A stored role named with an uppercase letter, and an entry under that name",
        { ...tabled, sr: { Analyst: [0] }, nt: { Analyst: { a: [[0]] } } },
      ],
      [
        "stored-role-named-as-permission-assigned",
        "A stored role named like reading, and an entry under that name",
        { ...tabled, sr: { "report:read": [0] }, nt: { "report:read": { a: [[0]] } } },
      ],
      ["places-not-a-list", "The place table written as one key", { ...zoe, pl: ACME }],
      [
        "permissions-not-a-list",
        "The permission table written as one string",
        { ...tabled, pm: "report:read" },
      ],
      [
        "presets-as-list",
        "The preset table written as a list",
        { ...without(tabled, "sr"), ps: [["writer", 0]] },
      ],
      [
        "stored-roles-as-rows",
        "Stored roles as rows of positions, the form of an earlier draft",
        { ...tabled, sr: [[0, 1]] },
      ],
      [
        "definition-not-a-list",
        "A definition written as one position",
        { ...tabled, sr: { analyst: 0 } },
      ],
      [
        "permission-twice-in-table",
        "A permission written twice in the permission table",
        { ...tabled, pm: ["report:read", "report:read"] },
      ],
      [
        "definition-permission-by-name",
        "A definition naming a concrete permission by its name",
        { ...tabled, sr: { analyst: ["report:read"] } },
      ],
      [
        "definition-permission-by-name-no-table",
        "A definition naming a concrete permission by its name, in grants with no permission table",
        { ...without(tabled, "pm"), sr: { analyst: ["report:read"] } },
      ],
      [
        "definition-exclusion-by-name",
        "A definition excluding a concrete permission by its name",
        { ...tabled, sr: { analyst: ["report:*", "-report:write"] } },
      ],
      [
        "definition-position-missing",
        "A definition naming a position the permission table does not hold",
        { ...tabled, sr: { analyst: [0, 2] } },
      ],
      [
        "definition-position-no-table",
        "A definition naming a position in grants with no permission table",
        { ...without(tabled, "pm"), sr: { analyst: [0] } },
      ],
      [
        "definition-exclusion-missing",
        "A definition excluding a position the permission table does not hold",
        { ...tabled, sr: { analyst: ["report:*", "-2"] } },
      ],
      [
        "definition-exclusion-leading-zero",
        "A definition excluding `-01`",
        { ...tabled, sr: { analyst: ["report:*", "-01"] } },
      ],
      [
        "definition-bare-dash",
        "A definition holding `-` alone",
        { ...tabled, sr: { analyst: [0, "-"] } },
      ],
      [
        "definition-double-dash",
        "A definition holding `--writer`",
        { ...tabled, sr: { analyst: [0, "--writer"] } },
      ],
      [
        "definition-negative-position",
        "A definition holding a negative integer",
        { ...tabled, sr: { analyst: [-1] } },
      ],
      [
        "definition-fractional-position",
        "A definition holding a fractional position",
        { ...tabled, sr: { analyst: [0.5] } },
      ],
      [
        "definition-position-as-string",
        "A definition holding a position written as a string without `-`",
        { ...tabled, sr: { analyst: ["0"] } },
      ],
      [
        "definition-star-star",
        "A definition holding `*:*`",
        { ...tabled, sr: { analyst: ["*:*"] } },
      ],
      [
        "definition-role-uppercase",
        "A definition naming a role with an uppercase letter",
        { ...tabled, sr: { analyst: ["Writer"] } },
      ],
      ["definition-null", "A definition holding `null`", { ...tabled, sr: { analyst: [null] } }],
      [
        "entry-unknown-member",
        "An entry holding a member other than a, d and x",
        { ...zoe, nt: { "report:*": { a: [[0]], z: [[0]] } } },
      ],
      [
        "entry-deny-under-role",
        "A deny under a role name",
        { ...tabled, nt: { analyst: { a: [[0]], d: [[0]] } } },
      ],
      [
        "entry-exclusion-under-role",
        "An exclusion under a role name",
        { ...tabled, nt: { analyst: { x: [[0]] } } },
      ],
      [
        "entry-as-list",
        "An entry written as a list of items",
        { ...zoe, nt: { "report:*": [[0]] } },
      ],
      [
        "entry-items-not-a-list",
        "An entry whose `a` is a number",
        { ...zoe, nt: { "report:*": { a: 0 } } },
      ],
      [
        "item-too-long",
        "An item of four elements",
        { ...zoe, nt: { "report:*": { a: [[0, null, 1, 2]] } } },
      ],
      [
        "item-place-missing",
        "An item naming a place the table does not hold",
        { ...zoe, nt: { "report:*": { a: [[3]] } } },
      ],
      [
        "item-place-negative",
        "An item naming a negative place index",
        { ...zoe, nt: { "report:*": { a: [[-1]] } } },
      ],
      [
        "item-place-fraction",
        "An item naming a fractional place index",
        { ...zoe, nt: { "report:*": { a: [[0.5]] } } },
      ],
      [
        "item-end-in-milliseconds",
        "An end counted in milliseconds",
        { ...zoe, nt: { "report:*": { a: [[0, FRIDAY_MIDNIGHT * 1000]] } } },
      ],
      [
        "item-end-as-string",
        "An end written as a string",
        { ...zoe, nt: { "report:*": { a: [[0, String(FRIDAY_MIDNIGHT)]] } } },
      ],
      ["item-end-negative", "An end before 1970", { ...zoe, nt: { "report:*": { a: [[0, -1]] } } }],
      [
        "item-bundle-zero",
        "A bundle numbered 0",
        { ...zoe, nt: { "report:*": { a: [[0, null, 0]] } } },
      ],
      [
        "item-bundle-negative",
        "A negative bundle number",
        { ...zoe, nt: { "report:*": { a: [[0, null, -1]] } } },
      ],
      [
        "item-bundle-over-cap",
        "A bundle number past the largest value a time may take",
        { ...zoe, nt: { "report:*": { a: [[0, null, LAST_TIME + 1]] } } },
      ],
      [
        "item-bundle-fraction",
        "A fractional bundle number",
        { ...zoe, nt: { "report:*": { a: [[0, null, 1.5]] } } },
      ],
      [
        "item-bundle-on-deny",
        "A deny carrying a bundle number",
        { ...zoe, nt: { ...zoe.nt, "report:read": { d: [[0, null, 1]] } } },
      ],
      [
        "item-not-a-list",
        "An item written as a number",
        { ...zoe, nt: { "report:*": { a: [0] } } },
      ],
    ],
    null,
  ),
  ...unread([
    [
      "place-lowercase-hex",
      "A deny of reading at a place key in lowercase hexadecimal: no key on the chain is spelled so, and the item is passed over",
      { ...zoe, pl: [ACME, "/org=caf%c3%a9"], nt: { ...zoe.nt, "report:read": { d: [[1]] } } },
      "allowed",
    ],
    [
      "root-in-places",
      "The root written in the place table: an item pointing at it is byte-equal to the root on the chain, and counts there",
      { ...zoe, pl: ["/"] },
      "allowed",
    ],
    [
      "permission-uppercase-in-table",
      "A permission spelled with an uppercase letter in the permission table, not the one looked up",
      { ...tabled, pm: ["Report:read", "report:write"], sr: { analyst: [1] } },
      "allowed",
    ],
    [
      "pattern-in-table",
      "A pattern in the permission table, not the permission looked up",
      { ...tabled, pm: ["report:*", "report:write"], sr: { analyst: [1] } },
      "allowed",
    ],
    [
      "number-in-table",
      "A number in the permission table, not the permission looked up",
      { ...tabled, pm: [0, "report:write"], sr: { analyst: [1] } },
      "allowed",
    ],
    [
      "name-in-both-tables",
      "A name both a preset copy that gives nothing and a stored role that reads: the read finds the copy first",
      { ...tabled, ps: { analyst: [] } },
      "denied",
    ],
    [
      "stored-role-name-uppercase",
      "A stored role named with an uppercase letter that no entry is found under: its name is never checked, and the entry analyst names a role in no table",
      { ...tabled, sr: { Analyst: [0] } },
      "denied",
    ],
    [
      "stored-role-named-as-permission",
      "A stored role named like reading that no entry is found under: every report permission given at the organisation answers",
      { ...tabled, sr: { "report:read": [0] }, nt: { "report:*": { a: [[0]] } } },
      "allowed",
    ],
    [
      "preset-copy-named-as-position",
      "A preset copy named like a position that no entry is found under: the stored analyst answers",
      { ...tabled, ps: { "0": [0] } },
      "allowed",
    ],
    [
      "entry-permission-by-name-beside-table",
      "An entry naming writing by its name beside a permission table, where a read looks for its position: Ann's stored analyst answers",
      { ...tabled, nt: { ...tabled.nt, "report:write": { a: [[0]] } } },
      "allowed",
    ],
    [
      "entry-position-no-table",
      "An entry named `0` in grants with no permission table, where a read looks for names: the rest answers",
      { ...zoe, nt: { ...zoe.nt, "0": { d: [[0]] } } },
      "allowed",
    ],
    [
      "entry-position-leading-zero",
      "An entry named `01` beside the entry of the stored analyst: the analyst answers",
      { ...tabled, nt: { ...tabled.nt, "01": { d: [[0]] } } },
      "allowed",
    ],
    [
      "entry-position-missing",
      "An entry naming a position the permission table does not hold: the analyst answers",
      { ...tabled, nt: { ...tabled.nt, "2": { d: [[0]] } } },
      "allowed",
    ],
    [
      "entry-excluded-position",
      "An entry named `-0`: the analyst answers",
      { ...tabled, nt: { ...tabled.nt, "-0": { d: [[0]] } } },
      "allowed",
    ],
    [
      "entry-row-of-earlier-draft",
      "An entry named `#0`, a role row of an earlier draft: the analyst answers",
      { ...tabled, nt: { ...tabled.nt, "#0": { a: [[0]] } } },
      "allowed",
    ],
    [
      "entry-star-star",
      "A deny under `*:*`, which is not a spelling of `*`: it is never looked up and blocks nothing",
      { ...zoe, nt: { ...zoe.nt, "*:*": { d: [[0]] } } },
      "allowed",
    ],
    [
      "entry-uppercase",
      "A deny under `Report:read`, another spelling of reading: it is never looked up and blocks nothing",
      { ...zoe, nt: { ...zoe.nt, "Report:read": { d: [[0]] } } },
      "allowed",
    ],
    [
      "item-ended-at-place-in-another-spelling",
      "An ended item of an entry the question reads names a place in lowercase hexadecimal: passed over like any place off the chain",
      {
        ...zoe,
        pl: [ACME, "/org=caf%c3%a9"],
        nt: { ...zoe.nt, "report:*": { a: [[0], [1, MONDAY + DAY]] } },
      },
      "allowed",
    ],
    [
      "entry-empty-name",
      "A deny under an empty name: it is never looked up and blocks nothing",
      { ...zoe, nt: { ...zoe.nt, "": { d: [[0]] } } },
      "allowed",
    ],
  ]),
];

function refused(
  cases: readonly (readonly [string, string, unknown])[],
  told: ExpectedDiverged,
): GrantsCase[] {
  return cases.map(([id, title, grants]) =>
    readCase(
      `malformed-${id}`,
      title,
      { catalog: reports, grants, expect: "ERR_AUTHZ_MALFORMED", diverged: told },
      "report:read",
      ACME,
    ),
  );
}

function unread(
  cases: readonly (readonly [string, string, unknown, "allowed" | "denied"])[],
): GrantsCase[] {
  return cases.map(([id, title, grants, expect]) =>
    readCase(
      `malformed-${id}`,
      title,
      { catalog: reports, grants, expect, whole: "ERR_AUTHZ_MALFORMED", diverged: null },
      "report:read",
      ACME,
    ),
  );
}
