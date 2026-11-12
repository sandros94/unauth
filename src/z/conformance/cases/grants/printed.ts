import type { GrantsCase } from "../../types.ts";
import {
  ACME,
  ARCHIVES,
  DAY,
  FRIDAY_MIDNIGHT,
  MONDAY,
  NEXT_MONDAY,
  U7,
  ada,
  adaByName,
  adaCopies,
  adaLater,
  diverged,
  edByName,
  edCopies,
  flat,
  readCase,
  reports,
  sue,
  zoe,
} from "./_internal/model.ts";

const THURSDAY = MONDAY + 3 * DAY;
const SATURDAY = MONDAY + 5 * DAY;

/**
 * The grants objects Section 8.4 of the model prints, copied with `ct` substituted, and the
 * answers its text states or implies.
 */
export const printedCases: readonly GrantsCase[] = [
  readCase(
    "zoe-reads",
    "Zoe reads at the organisation, and nothing has diverged",
    { catalog: reports, grants: zoe, expect: "allowed", diverged: null },
    "report:read",
    ACME,
  ),
  readCase(
    "zoe-does-not-write",
    "Zoe's exclusion takes writing out",
    { catalog: reports, grants: zoe, expect: "denied" },
    "report:write",
    ACME,
  ),
  readCase(
    "sue-writes-thursday",
    "Sue's own allow is in no bundle: the team's exclusion leaves it, on Thursday she writes in the archives",
    { catalog: reports, grants: sue, expect: "allowed", at: THURSDAY },
    "report:write",
    ARCHIVES,
  ),
  readCase(
    "sue-denied-saturday",
    "On Saturday Sue's own allow has ended and the team's bundle is closed in the archives",
    { catalog: reports, grants: sue, expect: "denied", at: SATURDAY },
    "report:write",
    ARCHIVES,
  ),
  readCase(
    "sue-writes-elsewhere-saturday",
    "Outside the archives the team's writer still gives writing on Saturday",
    { catalog: reports, grants: sue, expect: "allowed", at: SATURDAY },
    "report:write",
    ACME,
  ),
  readCase(
    "sue-reads-in-archives-saturday",
    "In the archives the team's exclusion takes writing alone: Sue still reads there on Saturday",
    { catalog: reports, grants: sue, expect: "allowed", at: SATURDAY },
    "report:read",
    ARCHIVES,
  ),
  ...edCases("ed-by-name", "presets by name", edByName),
  ...edCases("ed-copies", "copies of both presets", edCopies),
  ...(
    [
      [
        "reads-reports",
        "Ada reads reports at the organisation through viewer",
        "report:read",
        ACME,
        "allowed",
      ],
      [
        "writes-reports",
        "Ada writes reports at the organisation through reviewer",
        "report:write",
        ACME,
        "allowed",
      ],
      [
        "reads-posts",
        "Ada reads posts at the organisation through viewer",
        "post:read",
        ACME,
        "allowed",
      ],
      [
        "no-billing-at-org",
        "Reviewer excludes billing: Ada does not read it at the organisation",
        "billing:read",
        ACME,
        "denied",
      ],
      [
        "billing-at-her-unit",
        "Ada's allow by position 0 gives billing at her unit",
        "billing:read",
        U7,
        "allowed",
      ],
      [
        "no-billing-next-unit",
        "Her allow of billing does not reach the next unit",
        "billing:read",
        "/org=acme/unit=u8",
        "denied",
      ],
      [
        "nothing-at-root",
        "Reviewer is assigned at the organisation, not at the root",
        "report:write",
        "/",
        "denied",
      ],
    ] as const
  ).flatMap(([id, title, permission, place, expect]) => [
    readCase(
      `ada-copies-${id}`,
      `${title}, with copies`,
      { catalog: ada, grants: adaCopies, expect },
      permission,
      place,
    ),
    readCase(
      `ada-by-name-${id}`,
      `${title}, presets by name`,
      { catalog: ada, grants: adaByName, expect },
      permission,
      place,
    ),
  ]),
  readCase(
    "ada-copies-same-catalog",
    "Ada's grants with copies, read under the catalog they were issued under: nothing has diverged",
    { catalog: ada, grants: adaCopies, expect: "allowed", diverged: null },
    "report:read",
    ACME,
  ),
  readCase(
    "ada-copies-later-viewer",
    "A later catalog makes viewer read posts only: Ada's copy still reads reports, and the read says the copy diverged",
    {
      catalog: adaLater,
      issuedUnder: ada,
      grants: adaCopies,
      expect: "allowed",
      diverged: diverged(["presets"], { presets: ["viewer"] }),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "ada-copies-later-still-no-billing",
    "Under the later catalog Ada's reviewer still excludes billing at the organisation",
    { catalog: adaLater, issuedUnder: ada, grants: adaCopies, expect: "denied" },
    "billing:read",
    ACME,
  ),
  readCase(
    "ada-by-name-later-viewer",
    "The same grants without copies, under the later catalog: refused, nothing says what viewer meant",
    {
      catalog: adaLater,
      issuedUnder: ada,
      grants: adaByName,
      expect: "ERR_AUTHZ_GRANTS_CATALOG",
      diverged: "ERR_AUTHZ_GRANTS_CATALOG",
    },
    "report:read",
    ACME,
  ),
  readCase(
    "members-in-another-order",
    "Sue's grants written by another engine, members, places, items and entries in another order",
    {
      catalog: reports,
      grants: {
        nt: {
          "writer": { a: [[1, null, 1]] },
          "report:write": { x: [[0, null, 1]], a: [[1, FRIDAY_MIDNIGHT]] },
        },
        pl: [ARCHIVES, ACME],
        at: MONDAY,
        ct: "$ct",
        v: "1",
      },
      expect: "allowed",
      at: THURSDAY,
    },
    "report:write",
    ARCHIVES,
  ),
  readCase(
    "other-bundle-numbers",
    "Another engine numbers the team's bundle 7: it still closes only the team's values",
    {
      catalog: reports,
      grants: {
        ...sue,
        nt: {
          "report:write": { a: [[0, FRIDAY_MIDNIGHT]], x: [[1, null, 7]] },
          "writer": { a: [[0, null, 7]] },
        },
      },
      expect: "allowed",
      at: THURSDAY,
    },
    "report:write",
    ARCHIVES,
  ),
  readCase(
    "application-members-ignored",
    "Members of the application's own beside the grants are ignored",
    {
      catalog: reports,
      grants: { ...zoe, sid: "s-81f", exp: MONDAY + DAY, roles: ["anything"] },
      expect: "allowed",
    },
    "report:read",
    ACME,
  ),
  readCase(
    "duplicated-item",
    "The same item written twice changes nothing",
    { catalog: flat, grants: { ...edByName, nt: { viewer: { a: [[], []] } } }, expect: "allowed" },
    "post:read",
  ),
  readCase(
    "not-covered",
    "Grants for one organisation do not speak for another",
    { catalog: reports, grants: { ...zoe, bs: [ACME] }, expect: "not-covered" },
    "report:read",
    "/org=globex",
  ),
  readCase(
    "root-base-covers-everything",
    "Grants whose only base is written as the root speak for another organisation too: denied there, not uncovered",
    { catalog: reports, grants: { ...zoe, bs: ["/"] }, expect: "denied" },
    "report:read",
    "/org=globex",
  ),
  readCase(
    "other-format",
    "Grants of another format revision",
    {
      catalog: reports,
      grants: { ...zoe, v: "2" },
      expect: "ERR_AUTHZ_GRANTS_FORMAT",
      diverged: "ERR_AUTHZ_GRANTS_FORMAT",
    },
    "report:read",
    ACME,
  ),
  readCase(
    "read-one-second-early",
    "A read one second before the grants were issued",
    { catalog: reports, grants: zoe, expect: "ERR_AUTHZ_GRANTS_EARLY", at: MONDAY - 1 },
    "report:read",
    ACME,
  ),
];

function edCases(id: string, how: string, grants: unknown): GrantsCase[] {
  return [
    readCase(
      `${id}-edits-before-monday`,
      `Ed, in an application without places, edits until next Monday, ${how}`,
      { catalog: flat, grants, expect: "allowed", at: MONDAY + DAY, diverged: null },
      "post:write",
    ),
    readCase(
      `${id}-reads-through-editor`,
      `Ed reads posts, ${how}`,
      { catalog: flat, grants, expect: "allowed", at: MONDAY + DAY },
      "post:read",
    ),
    readCase(
      `${id}-editor-ended`,
      `At the second Ed's editor ends it no longer counts, ${how}`,
      { catalog: flat, grants, expect: "denied", at: NEXT_MONDAY },
      "post:write",
    ),
    readCase(
      `${id}-still-views`,
      `Ed's permanent viewer still reads after his editor ended, ${how}`,
      { catalog: flat, grants, expect: "allowed", at: NEXT_MONDAY + DAY },
      "post:read",
    ),
  ];
}
