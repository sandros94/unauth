import type { GrantsCase } from "../../types.ts";
import {
  ACME,
  FRIDAY_MIDNIGHT,
  LAST_TIME,
  MONDAY,
  diverged,
  readCase,
  reports,
  zoe,
} from "./_internal/model.ts";

/** Grants with a permission table and a stored role, `analyst`, assigned at the organisation. */
const tabled = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME],
  pm: ["report:read", "report:write"],
  sr: { analyst: [0] },
  nt: { analyst: { a: [[0]] } },
};

/**
 * The checks of form of Section 8.4, each with grants that pass it and grants that fail it, and
 * grants that name what the catalog does not know, which are read, never refused.
 */
export const formCases: readonly GrantsCase[] = [
  ...read([
    [
      "permission-table-beside-no-role-table",
      "A permission table with no role table: entries name permissions by position, patterns by name",
      { ...zoe, pm: ["report:write"], nt: { "report:*": { a: [[0]] }, "0": { x: [[0]] } } },
      "report:write",
      "denied",
    ],
    [
      "permission-table-in-another-order",
      "A permission table not in byte order is read by its positions as written",
      { ...tabled, pm: ["report:write", "report:read"], sr: { analyst: [1] } },
      "report:read",
      "allowed",
    ],
    [
      "permission-table-in-another-order-gives-no-more",
      "A permission table not in byte order gives only what its positions name",
      { ...tabled, pm: ["report:write", "report:read"], sr: { analyst: [1] } },
      "report:write",
      "denied",
    ],
    [
      "definition-excludes-by-position",
      "A definition of a pattern and `-1`: the stored role gives every report permission but writing",
      { ...tabled, sr: { analyst: ["report:*", "-1"] } },
      "report:write",
      "denied",
    ],
    [
      "definition-excludes-by-position-leaves-the-rest",
      "The same definition still gives reading",
      { ...tabled, sr: { analyst: ["report:*", "-1"] } },
      "report:read",
      "allowed",
    ],
    [
      "definition-excludes-a-pattern",
      "A definition that names the writer preset and excludes `report:*` gives nothing",
      { ...tabled, sr: { analyst: ["writer", "-report:*"] } },
      "report:read",
      "denied",
    ],
    [
      "definition-excludes-a-role",
      "A definition that excludes another stored role takes out what it gives and what implies it",
      { ...tabled, sr: { analyst: ["writer", "-auditor"], auditor: [0] } },
      "report:write",
      "denied",
    ],
    [
      "deny-by-position",
      "Beside a permission table a deny named by its position blocks what implies it",
      { ...tabled, sr: { analyst: [1] }, nt: { "analyst": { a: [[0]] }, "0": { d: [[0]] } } },
      "report:write",
      "denied",
    ],
    [
      "exclusion-by-position",
      "Beside a permission table an exclusion named by its position takes its permission out",
      { ...tabled, sr: { analyst: [0, 1] }, nt: { "analyst": { a: [[0]] }, "1": { x: [[0]] } } },
      "report:write",
      "denied",
    ],
    [
      "exclusion-by-position-leaves-the-rest",
      "An exclusion named by its position leaves the role's other permissions",
      { ...tabled, sr: { analyst: [0, 1] }, nt: { "analyst": { a: [[0]] }, "1": { x: [[0]] } } },
      "report:read",
      "allowed",
    ],
    [
      "pattern-keeps-its-name-beside-a-table",
      "Beside a permission table a pattern keeps its name",
      { ...tabled, nt: { "report:*": { a: [[0]] } } },
      "report:write",
      "allowed",
    ],
    [
      "deny-under-a-pattern",
      "A deny under a pattern blocks what it matches",
      { ...zoe, nt: { "report:*": { a: [[0]], d: [[0]] } } },
      "report:read",
      "denied",
    ],
    [
      "item-root-in-a-bundle",
      "`[null,null,2]`, the root in bundle 2",
      { ...zoe, nt: { "report:*": { a: [[null, null, 2]] } } },
      "report:read",
      "allowed",
    ],
    [
      "item-trailing-null-written",
      "An item that writes its trailing `null`",
      { ...zoe, nt: { "report:*": { a: [[0, null]] } } },
      "report:read",
      "allowed",
    ],
    [
      "item-largest-bundle",
      "A bundle numbered with the largest value a time may take",
      { ...zoe, nt: { "report:*": { a: [[0, null, LAST_TIME]] } } },
      "report:read",
      "allowed",
    ],
    [
      "undeclared-permission-in-table",
      "A permission table holding a permission the catalog does not declare: read, that permission is inert",
      { ...tabled, pm: ["legacy:export", "report:read"], sr: { analyst: [0, 1] } },
      "report:read",
      "allowed",
    ],
    [
      "undeclared-permission-by-position",
      "An allow of a permission the catalog does not declare, named by its position: read",
      {
        ...tabled,
        pm: ["billing:read", "report:read"],
        nt: { "0": { a: [[0]] }, "1": { a: [[0]] } },
      },
      "report:read",
      "allowed",
    ],
    [
      "undeclared-permission-by-name",
      "An entry named after a permission the catalog does not declare: read, that entry is inert",
      { ...zoe, nt: { ...zoe.nt, "billing:read": { a: [[0]] } } },
      "report:read",
      "allowed",
    ],
    [
      "pattern-matching-nothing",
      "An entry named after a pattern that matches no declared permission: read",
      { ...zoe, nt: { ...zoe.nt, "invoice:*": { d: [[0]] } } },
      "report:read",
      "allowed",
    ],
    [
      "place-outside-structure",
      "A place the structure does not hold, in the place table: read, what sits there applies nowhere",
      { ...zoe, pl: [ACME, "/org=acme/team=t1"], nt: { ...zoe.nt, "report:read": { d: [[1]] } } },
      "report:read",
      "allowed",
    ],
    [
      "root-as-only-base",
      "The root written as the only base: read, it covers everything",
      { ...zoe, bs: ["/"] },
      "report:read",
      "allowed",
    ],
    ...(
      [
        [
          "empty-entry-permission",
          "An entry under a permission with no member",
          { "report:read": {} },
        ],
        [
          "empty-items-permission",
          "An entry under a permission whose `a` holds no item",
          { "report:read": { a: [] } },
        ],
        ["empty-entry-role", "An entry under a role name with no member", { writer: {} }],
        [
          "empty-items-role",
          "An entry under a role name whose `a` holds no item",
          { writer: { a: [] } },
        ],
        ["empty-entry-pattern", "An entry under a pattern with no member", { "report:*": {} }],
        [
          "empty-items-pattern",
          "An entry under a pattern whose members hold no item",
          { "report:*": { a: [], d: [], x: [] } },
        ],
      ] as const
    ).map(
      ([id, title, nt]) =>
        [id, `${title}: read, it says nothing`, { ...zoe, nt }, "report:read", "denied"] as const,
    ),
    [
      "empty-deny-beside-allow",
      "A deny under reading that holds no item, beside an allow of every report permission: it blocks nothing",
      { ...zoe, nt: { "report:*": { a: [[0]] }, "report:read": { d: [] } } },
      "report:read",
      "allowed",
    ],
    [
      "role-in-no-table-by-name",
      "An entry naming a role neither table holds nor the catalog declares, presets by name: read, it gives nothing",
      { ...zoe, nt: { ghost: { a: [[0]] } } },
      "report:read",
      "denied",
    ],
    [
      "role-in-no-table-with-copies",
      "An entry naming a role neither table holds, beside preset copies: read, it gives nothing",
      { ...without(tabled, "sr"), ps: { writer: [0, 1] }, nt: { ghost: { a: [[0]] } } },
      "report:read",
      "denied",
    ],
  ]),
  ...refused([
    ["no-revision", "No format revision", without(zoe, "v")],
    ["revision-as-number", "The format revision written as the number 1", { ...zoe, v: 1 }],
    ["no-fingerprint", "No catalog fingerprint", without(zoe, "ct")],
    ["no-time", "No time of issue", without(zoe, "at")],
    ["no-entries", "No entries", without(zoe, "nt")],
    ["time-as-string", "The time of issue written as a string", { ...zoe, at: String(MONDAY) }],
    ["time-fraction", "A time of issue with a fraction", { ...zoe, at: MONDAY + 0.5 }],
    ["time-over-cap", "A time of issue past the year 9999", { ...zoe, at: LAST_TIME + 1 }],
    ["time-negative", "A time of issue before 1970", { ...zoe, at: -1 }],
    ["entries-as-list", "Entries written as a list", { ...zoe, nt: [["report:*", { a: [[0]] }]] }],
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
    [
      "place-lowercase-hex",
      "A place key with lowercase hexadecimal",
      { ...zoe, pl: ["/org=caf%c3%a9"] },
    ],
    ["root-in-places", "The root written in the place table", { ...zoe, pl: ["/"] }],
    ["base-trailing-slash", "A base key ending in `/`", { ...zoe, bs: ["/org=acme/"] }],
    ["base-not-a-key", "A base written without its leading `/`", { ...zoe, bs: ["org=acme"] }],
    [
      "permission-uppercase-in-table",
      "A permission spelled with an uppercase letter in the permission table",
      { ...tabled, pm: ["Report:read", "report:write"] },
    ],
    [
      "pattern-in-table",
      "A pattern in the permission table",
      { ...tabled, pm: ["report:*", "report:write"] },
    ],
    [
      "permission-twice-in-table",
      "A permission written twice in the permission table",
      { ...tabled, pm: ["report:read", "report:read"] },
    ],
    ["number-in-table", "A number in the permission table", { ...tabled, pm: [0, "report:write"] }],
    [
      "name-in-both-tables",
      "A name both a preset copy and a stored role",
      { ...tabled, ps: { analyst: [1] } },
    ],
    [
      "stored-role-name-uppercase",
      "A stored role named with an uppercase letter",
      { ...tabled, sr: { Analyst: [0] } },
    ],
    [
      "stored-role-named-as-permission",
      "A stored role named like a permission",
      { ...tabled, sr: { "report:read": [0] }, nt: { "report:*": { a: [[0]] } } },
    ],
    [
      "preset-copy-named-as-position",
      "A preset copy named like a position",
      { ...tabled, ps: { "0": [0] } },
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
    ["definition-star-star", "A definition holding `*:*`", { ...tabled, sr: { analyst: ["*:*"] } }],
    [
      "definition-role-uppercase",
      "A definition naming a role with an uppercase letter",
      { ...tabled, sr: { analyst: ["Writer"] } },
    ],
    ["definition-null", "A definition holding `null`", { ...tabled, sr: { analyst: [null] } }],
    [
      "entry-permission-by-name-beside-table",
      "An entry naming a permission by its name in grants that hold a permission table",
      { ...tabled, nt: { ...tabled.nt, "report:write": { a: [[0]] } } },
    ],
    [
      "entry-position-no-table",
      "An entry naming a position in grants that hold no permission table",
      { ...zoe, nt: { "0": { a: [[0]] } } },
    ],
    [
      "entry-position-leading-zero",
      "An entry named `01`",
      { ...tabled, nt: { ...tabled.nt, "01": { a: [[0]] } } },
    ],
    [
      "entry-position-missing",
      "An entry naming a position the permission table does not hold",
      { ...tabled, nt: { ...tabled.nt, "2": { a: [[0]] } } },
    ],
    [
      "entry-excluded-position",
      "An entry named `-0`",
      { ...tabled, nt: { ...tabled.nt, "-0": { a: [[0]] } } },
    ],
    [
      "entry-row-of-earlier-draft",
      "An entry named `#0`, a role row of an earlier draft",
      { ...tabled, nt: { "#0": { a: [[0]] } } },
    ],
    ["entry-star-star", "An entry named `*:*`", { ...zoe, nt: { "*:*": { a: [[0]] } } }],
    [
      "entry-uppercase",
      "An entry named with an uppercase letter",
      { ...zoe, nt: { "Report:read": { a: [[0]] } } },
    ],
    ["entry-empty-name", "An entry with an empty name", { ...zoe, nt: { "": { a: [[0]] } } }],
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
    ["entry-as-list", "An entry written as a list of items", { ...zoe, nt: { "report:*": [[0]] } }],
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
    ["item-not-a-list", "An item written as a number", { ...zoe, nt: { "report:*": { a: [0] } } }],
  ]),
  readCase(
    "form-foreign-fingerprint",
    "A fingerprint of two segments using every kind of character of the alphabet, of another catalog: grants naming no preset are read, and both segments are told",
    {
      catalog: reports,
      grants: { ...zoe, ct: "Az09-_az09A.Zz-_09azAZ0" },
      expect: "allowed",
      diverged: diverged(["permissions", "presets"]),
    },
    "report:read",
    ACME,
  ),
];

function read(
  cases: readonly (readonly [string, string, unknown, string, "allowed" | "denied"])[],
): GrantsCase[] {
  return cases.map(([id, title, grants, permission, expect]) =>
    readCase(`form-${id}`, title, { catalog: reports, grants, expect }, permission, ACME),
  );
}

function refused(cases: readonly (readonly [string, string, unknown])[]): GrantsCase[] {
  return cases.map(([id, title, grants]) =>
    readCase(
      `malformed-${id}`,
      title,
      { catalog: reports, grants, expect: "ERR_AUTHZ_MALFORMED", diverged: "ERR_AUTHZ_MALFORMED" },
      "report:read",
      ACME,
    ),
  );
}

function without<T extends object, K extends keyof T>(value: T, member: K): Omit<T, K> {
  const { [member]: _dropped, ...rest } = value;
  return rest;
}
