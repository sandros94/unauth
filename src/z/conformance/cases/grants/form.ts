import type { GrantsCase } from "../../types.ts";
import {
  ACME,
  LAST_TIME,
  diverged,
  readCase,
  reports,
  tabled,
  without,
  zoe,
} from "./_internal/model.ts";

/**
 * The checks of form of Section 8.4 met by grants that pass them, and grants that name what the
 * catalog does not know, which are read, never refused.
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
  readCase(
    "form-foreign-fingerprint",
    "A fingerprint of two segments using every kind of character of the alphabet, of another catalog: read, and both segments are told",
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
