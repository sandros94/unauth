import type { CatalogData } from "../../catalog.ts";
import type { GrantsCase } from "../types.ts";

const ARCHIVES = "/org=acme/area=archives";
const DAY = 86400;
const MONDAY = 1794214800;
const FRIDAY_MIDNIGHT = 1794528000;
const THURSDAY = MONDAY + 3 * DAY;
const SATURDAY = MONDAY + 5 * DAY;
const NEXT_MONDAY = 1794819600;

const reports: CatalogData = {
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { writer: ["report:read", "report:write"] },
  places: { "/": ["org"], "org": ["area"] },
};

const flat: CatalogData = {
  permissions: ["post:read", "post:edit"],
  presets: { viewer: ["post:read"], editor: ["post:edit"] },
  places: false,
};

const zoe = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: ["/org=acme"],
  nt: { "report:*": { a: [[0]] }, "report:write": { x: [[0]] } },
};

const sue = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: ["/org=acme", ARCHIVES],
  nt: {
    "report:write": { a: [[0, FRIDAY_MIDNIGHT]], x: [[1, null, 1]] },
    "writer": { a: [[0, null, 1]] },
  },
};

const ed = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  nt: { editor: { a: [[null, NEXT_MONDAY]] }, viewer: { a: [[]] } },
};

export const grantsCases: readonly GrantsCase[] = [
  zoeCase("zoe-reads", "Zoe reads at the organisation", zoe, "report:read", "allowed"),
  zoeCase("zoe-does-not-write", "Zoe's exclusion takes writing out", zoe, "report:write", "denied"),
  {
    id: "grants/sue-writes-thursday",
    title:
      "Sue's own allow is in no bundle: the team's exclusion leaves it, on Thursday she writes in the archives",
    catalog: reports,
    grants: sue,
    at: THURSDAY,
    question: { permission: "report:write", place: ARCHIVES },
    expect: "allowed",
  },
  {
    id: "grants/sue-denied-saturday",
    title: "On Saturday Sue's own allow has ended and the team's bundle is closed in the archives",
    catalog: reports,
    grants: sue,
    at: SATURDAY,
    question: { permission: "report:write", place: ARCHIVES },
    expect: "denied",
  },
  {
    id: "grants/sue-writes-elsewhere-saturday",
    title: "Outside the archives the team's writer still gives writing on Saturday",
    catalog: reports,
    grants: sue,
    at: SATURDAY,
    question: { permission: "report:write", place: "/org=acme" },
    expect: "allowed",
  },
  {
    id: "grants/ed-edits-before-monday",
    title: "Ed, in an application without places, edits until next Monday",
    catalog: flat,
    grants: ed,
    at: MONDAY + DAY,
    question: { permission: "post:edit" },
    expect: "allowed",
  },
  {
    id: "grants/ed-editor-ended",
    title: "At the second Ed's editor ends, it no longer counts",
    catalog: flat,
    grants: ed,
    at: NEXT_MONDAY,
    question: { permission: "post:edit" },
    expect: "denied",
  },
  {
    id: "grants/ed-still-views",
    title: "Ed's permanent viewer still reads after his editor ended",
    catalog: flat,
    grants: ed,
    at: NEXT_MONDAY + DAY,
    question: { permission: "post:read" },
    expect: "allowed",
  },
  {
    id: "grants/members-in-another-order",
    title:
      "Sue's grants written by another engine, members, places, items and entries in another order",
    catalog: reports,
    grants: {
      nt: {
        "writer": { a: [[1, null, 1]] },
        "report:write": { x: [[0, null, 1]], a: [[1, FRIDAY_MIDNIGHT]] },
      },
      pl: [ARCHIVES, "/org=acme"],
      at: MONDAY,
      ct: "$ct",
      v: "1",
    },
    at: THURSDAY,
    question: { permission: "report:write", place: ARCHIVES },
    expect: "allowed",
  },
  {
    id: "grants/other-bundle-numbers",
    title: "Another engine numbers the team's bundle 7: it still closes only the team's values",
    catalog: reports,
    grants: {
      ...sue,
      nt: {
        "report:write": { a: [[0, FRIDAY_MIDNIGHT]], x: [[1, null, 7]] },
        "writer": { a: [[0, null, 7]] },
      },
    },
    at: THURSDAY,
    question: { permission: "report:write", place: ARCHIVES },
    expect: "allowed",
  },
  zoeCase(
    "unknown-member-ignored",
    "Members of the application's own beside the grants are ignored",
    { ...zoe, sid: "s-81f", exp: MONDAY + DAY, roles: ["anything"] },
    "report:read",
    "allowed",
  ),
  {
    id: "grants/duplicated-item",
    title: "The same item written twice changes nothing",
    catalog: flat,
    grants: { ...ed, nt: { viewer: { a: [[], []] } } },
    at: MONDAY,
    question: { permission: "post:read" },
    expect: "allowed",
  },
  zoeCase(
    "not-covered",
    "Grants for one organisation do not speak for another",
    { ...zoe, bs: ["/org=acme"] },
    "report:read",
    "not-covered",
    "/org=globex",
  ),
  zoeCase(
    "stored-role-row",
    "A stored role carried as the row of permissions it resolved to",
    { ...zoe, rl: [["report:read", "report:write"]], nt: { "#0": { a: [[0]] } } },
    "report:write",
    "allowed",
  ),
  zoeCase(
    "deny-reaches-implying",
    "A carried deny of reading also blocks writing",
    { ...zoe, nt: { "report:*": { a: [[0]] }, "report:read": { d: [[0]] } } },
    "report:write",
    "denied",
  ),
  ...malformed(),
  zoeCase(
    "other-format",
    "Grants of another format revision",
    { ...zoe, v: "2" },
    "report:read",
    "ERR_AUTHZ_GRANTS_FORMAT",
  ),
  zoeCase(
    "other-catalog",
    "Grants issued for another catalog",
    { ...zoe, ct: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
    "report:read",
    "ERR_AUTHZ_GRANTS_CATALOG",
  ),
  {
    id: "grants/read-one-second-early",
    title: "A read one second before the grants were issued",
    catalog: reports,
    grants: zoe,
    at: MONDAY - 1,
    question: { permission: "report:read", place: "/org=acme" },
    expect: "ERR_AUTHZ_GRANTS_EARLY",
  },
];

function malformed(): GrantsCase[] {
  const { at: _at, ...withoutAt } = zoe;
  const { nt: _nt, ...withoutEntries } = zoe;
  const cases: [string, string, unknown][] = [
    ["missing-at", "No time of issue", withoutAt],
    ["missing-entries", "No entries", withoutEntries],
    ["at-as-string", "The time of issue written as a string", { ...zoe, at: String(MONDAY) }],
    ["places-not-a-list", "The place table written as one key", { ...zoe, pl: "/org=acme" }],
    ["fraction-of-second", "A time of issue with a fraction", { ...zoe, at: MONDAY + 0.5 }],
    [
      "non-canonical-key",
      "A place key with lowercase hexadecimal",
      { ...zoe, pl: ["/org=caf%c3%a9"] },
    ],
    [
      "key-outside-structure",
      "A place key the structure does not hold",
      { ...zoe, pl: ["/org=acme/team=t1"] },
    ],
    ["root-in-places", "The root written in the place table", { ...zoe, pl: ["/"] }],
    [
      "unknown-permission-in-row",
      "A role row naming a permission the catalog does not declare",
      { ...zoe, rl: [["report:read", "legacy:export"]], nt: { "#0": { a: [[0]] } } },
    ],
    [
      "unknown-permission-entry",
      "An entry named after a permission the catalog does not declare",
      { ...zoe, nt: { "report:*": { a: [[0]] }, "billing:read": { a: [[0]] } } },
    ],
    [
      "pattern-matching-nothing",
      "An entry named after a pattern that matches no declared permission",
      { ...zoe, nt: { "report:*": { a: [[0]] }, "invoice:*": { d: [[0]] } } },
    ],
    [
      "row-out-of-range",
      "An entry naming a role row that does not exist",
      { ...zoe, rl: [["report:read"]], nt: { "#1": { a: [[0]] } } },
    ],
    [
      "place-out-of-range",
      "An item naming a place the table does not hold",
      { ...zoe, nt: { "report:*": { a: [[3]] } } },
    ],
    [
      "negative-place",
      "An item naming a negative place index",
      { ...zoe, nt: { "report:*": { a: [[-1]] } } },
    ],
    [
      "bundle-on-a-deny",
      "A deny carrying a bundle number",
      { ...zoe, nt: { "report:*": { a: [[0]] }, "report:read": { d: [[0, null, 1]] } } },
    ],
    ["bundle-zero", "A bundle numbered 0", { ...zoe, nt: { "report:*": { a: [[0, null, 0]] } } }],
    [
      "unknown-member-in-entry",
      "An entry holding a member other than a, d and x",
      { ...zoe, nt: { "report:*": { a: [[0]], z: [[0]] } } },
    ],
    [
      "exclusion-under-a-role-row",
      "An exclusion under a role row",
      { ...zoe, rl: [["report:read"]], nt: { "#0": { a: [[0]], x: [[0]] } } },
    ],
    [
      "item-too-long",
      "An item of four elements",
      { ...zoe, nt: { "report:*": { a: [[0, null, 1, 2]] } } },
    ],
    [
      "end-in-milliseconds",
      "An end counted in milliseconds",
      { ...zoe, nt: { "report:*": { a: [[0, FRIDAY_MIDNIGHT * 1000]] } } },
    ],
    ["not-an-object", "A string in place of grants", "grants"],
  ];
  return [
    ...cases.map(([id, title, grants]) =>
      zoeCase(id, title, grants, "report:read", "ERR_AUTHZ_MALFORMED"),
    ),
    {
      id: "grants/malformed-deny-under-preset",
      title: "A deny under a preset",
      catalog: reports,
      grants: { ...sue, nt: { writer: { a: [[0]], d: [[1]] } } },
      at: MONDAY,
      question: { permission: "report:read", place: ARCHIVES },
      expect: "ERR_AUTHZ_MALFORMED",
    },
  ];
}

function zoeCase(
  id: string,
  title: string,
  grants: unknown,
  permission: string,
  expect: GrantsCase["expect"],
  place = "/org=acme",
): GrantsCase {
  return {
    id: `grants/${expect === "ERR_AUTHZ_MALFORMED" ? "malformed-" : ""}${id}`,
    title,
    catalog: reports,
    grants,
    at: MONDAY,
    question: { permission, place },
    expect,
  };
}
