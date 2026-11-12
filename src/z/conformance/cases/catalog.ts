import type { CatalogData } from "../../catalog.ts";
import { DEPTH, IMPLIED, implicationChain, presetChain } from "../_internal/deep.ts";
import type { CatalogCase } from "../types.ts";

const reports: CatalogData = {
  permissions: ["report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { viewer: ["report:read"], editor: ["viewer", "report:write"] },
  places: { "/": ["org"], "org": ["unit"] },
};

/** The fingerprint of `reports`: its first segment, a `.`, and its second. */
const REPORTS = "NFb8S-LrGCw.sESKyO9Fmp0";

/** The second segment of every catalog that declares no preset: the hash of `{}`. */
const NO_PRESETS = "RBNvo1WzZ4o";

/** Reading and writing reports in organisations, nothing else. */
const plain: CatalogData = {
  permissions: ["report:read", "report:write"],
  places: { "/": ["org"] },
};

/** The fingerprint of `plain`. */
const PLAIN = "21K-UUdxg-s.RBNvo1WzZ4o";

export const catalogCases: readonly CatalogCase[] = [
  {
    id: "catalog/empty-implies-is-absent",
    title: "`implies` written with nothing in it: the same catalog as without it",
    catalog: { ...plain, implies: {} },
    expect: "accepted",
    fingerprint: PLAIN,
  },
  {
    id: "catalog/implies-empty-list-is-absent",
    title: "A permission mapped to an empty list in `implies`: the same catalog as without it",
    catalog: { ...plain, implies: { "report:write": [] } },
    expect: "accepted",
    fingerprint: PLAIN,
  },
  {
    id: "catalog/empty-presets-is-absent",
    title: "`presets` written with nothing in it: the same catalog as without it",
    catalog: { ...plain, presets: {} },
    expect: "accepted",
    fingerprint: PLAIN,
  },
  {
    id: "catalog/preset-with-no-entries",
    title:
      "A preset declared with no entries is a role all the same: kept, and the second segment moves",
    catalog: { ...plain, presets: { viewer: [] } },
    expect: "accepted",
    fingerprint: "21K-UUdxg-s.BBGmha0i7xg",
  },
  {
    id: "catalog/deep-preset-chain",
    title: `${DEPTH} presets, each built on the next, the last reading reports`,
    catalog: { ...plain, presets: presetChain(DEPTH, "report:read") },
    expect: "accepted",
  },
  {
    id: "catalog/deep-implication-chain",
    title: `${IMPLIED} permissions, each implying the next`,
    catalog: implicationChain(IMPLIED),
    expect: "accepted",
  },
  {
    id: "catalog/fingerprint-two-segments",
    title:
      "An application with reports, two presets and organisations of units: 11 characters for what it may do, 11 for its presets",
    catalog: reports,
    expect: "accepted",
    fingerprint: REPORTS,
  },
  {
    id: "catalog/fingerprint-preset-edited",
    title: "The viewer preset is widened to every report permission: only the second segment moves",
    catalog: { ...reports, presets: { viewer: ["report:*"], editor: ["viewer", "report:write"] } },
    expect: "accepted",
    fingerprint: "NFb8S-LrGCw.Z2CHBOBckpg",
  },
  {
    id: "catalog/fingerprint-permission-added",
    title: "Exporting reports is added to the catalog: only the first segment moves",
    catalog: { ...reports, permissions: ["report:read", "report:write", "report:export"] },
    expect: "accepted",
    fingerprint: "bktMjN2lXD4.sESKyO9Fmp0",
  },
  {
    id: "catalog/fingerprint-implication-removed",
    title: "Writing a report no longer implies reading it: only the first segment moves",
    catalog: {
      permissions: reports.permissions,
      presets: reports.presets,
      places: reports.places,
    },
    expect: "accepted",
    fingerprint: "WlqKv5y-4c8.sESKyO9Fmp0",
  },
  {
    id: "catalog/fingerprint-level-added",
    title: "Projects may now sit under an organisation: only the first segment moves",
    catalog: { ...reports, places: { "/": ["org"], "org": ["unit", "project"] } },
    expect: "accepted",
    fingerprint: "jLZVwmSTh0k.sESKyO9Fmp0",
  },
  {
    id: "catalog/fingerprint-order-and-repeats",
    title:
      "The same catalog written in another order, with lists repeating values: neither segment moves",
    catalog: {
      places: { "org": ["unit", "unit"], "/": ["org"] },
      presets: { editor: ["report:write", "viewer", "viewer"], viewer: ["report:read"] },
      implies: { "report:write": ["report:read", "report:read"] },
      permissions: ["report:write", "report:read"],
    },
    expect: "accepted",
    fingerprint: REPORTS,
  },
  {
    id: "catalog/fingerprint-no-presets-small",
    title: "A catalog of one permission and no preset: its second segment is the hash of `{}`",
    catalog: { permissions: ["doc:read"] },
    expect: "accepted",
    fingerprint: `jhaybtzHZyM.${NO_PRESETS}`,
  },
  {
    id: "catalog/fingerprint-no-presets-other",
    title:
      "Another catalog with no preset, with an implication and no places: another first segment, the same second",
    catalog: {
      permissions: ["doc:read", "doc:write"],
      implies: { "doc:write": ["doc:read"] },
      places: false,
    },
    expect: "accepted",
    fingerprint: `GgjlhVnRegE.${NO_PRESETS}`,
  },
  {
    id: "catalog/only-permissions",
    title: "A catalog that declares permissions and nothing else",
    catalog: { permissions: ["report:write", "report:read"] },
    expect: "accepted",
    fingerprint: "tqH3DB6_4qw.RBNvo1WzZ4o",
  },
  {
    id: "catalog/every-member",
    title: "A catalog that declares every member the model defines",
    catalog: {
      permissions: ["report:write", "report:read", "doc:read", "member:assign", "access:manage"],
      implies: { "report:write": ["report:read"] },
      presets: {
        viewer: ["*:read"],
        editor: ["viewer", "report:write", "-doc:read"],
        member: ["report:read"],
      },
      places: { "/": ["org"], "org": ["unit"], "*": ["folder"] },
    },
    expect: "accepted",
    fingerprint: "0yi4_ChkHao.2gobI249O8w",
  },
  {
    id: "catalog/order-and-repeats-a",
    title: "Members, lists and entries in one order, with repeats outside the permissions",
    catalog: {
      permissions: ["vm:start", "report:write", "report:read", "access:manage"],
      implies: { "report:write": ["report:read", "report:read"] },
      presets: {
        viewer: ["report:read", "report:read"],
        editor: ["viewer", "report:write", "viewer"],
      },
      places: { "org": ["unit", "project", "unit"], "/": ["org"] },
    },
    expect: "accepted",
    fingerprint: "kHwvGnidEsg.sESKyO9Fmp0",
  },
  {
    id: "catalog/order-and-repeats-b",
    title: "The same declarations in another order and without repeats: the same fingerprint",
    catalog: {
      places: { "/": ["org"], "org": ["project", "unit"] },
      presets: { editor: ["report:write", "viewer"], viewer: ["report:read"] },
      implies: { "report:write": ["report:read"] },
      permissions: ["access:manage", "report:read", "report:write", "vm:start"],
    },
    expect: "accepted",
    fingerprint: "kHwvGnidEsg.sESKyO9Fmp0",
  },
  {
    id: "catalog/places-false",
    title: "An application that declares it has no places",
    catalog: { permissions: ["report:read"], places: false },
    expect: "accepted",
    fingerprint: "J0DYiWQfEhQ.RBNvo1WzZ4o",
  },
  {
    id: "catalog/places-absent",
    title: "The same catalog saying nothing about places: another fingerprint",
    catalog: { permissions: ["report:read"] },
    expect: "accepted",
    fingerprint: "d-NW76kxxic.RBNvo1WzZ4o",
  },
  {
    id: "catalog/structure-star-parent",
    title: "A drive whose folders sit under the root and under every level",
    catalog: {
      permissions: ["file:read", "file:write"],
      places: { "*": ["folder"], "/": ["drive"] },
    },
    expect: "accepted",
    fingerprint: "GnBymVwZlNM.RBNvo1WzZ4o",
  },
  {
    id: "catalog/token-edges",
    title: "A resource of thirty-two characters, and tokens with digits, `_` and `-`",
    catalog: { permissions: ["abcdefghijklmnopqrstuvwxyz012345:read", "report_v2:read-all"] },
    expect: "accepted",
    fingerprint: "lxRqItyKgcA.RBNvo1WzZ4o",
  },
  {
    id: "catalog/implication-chain",
    title: "Implications that chain without a cycle",
    catalog: {
      permissions: ["report:list", "report:read", "report:write"],
      implies: { "report:write": ["report:read"], "report:read": ["report:list"] },
    },
    expect: "accepted",
    fingerprint: "IcfXcJ8QvOE.RBNvo1WzZ4o",
  },
  {
    id: "catalog/structure-chain",
    title: "A structure in which every parent level itself sits somewhere",
    catalog: {
      permissions: ["report:read"],
      places: { "/": ["org"], "org": ["unit"], "unit": ["team"] },
    },
    expect: "accepted",
    fingerprint: "9imCQZ5H1DY.RBNvo1WzZ4o",
  },
  {
    id: "catalog/preset-references",
    title: "Presets that reference and exclude other presets",
    catalog: {
      permissions: ["billing:read", "report:read", "report:write"],
      presets: {
        reader: ["*:read"],
        support: ["reader", "-billing:read"],
        lead: ["support", "-reader", "report:write"],
      },
    },
    expect: "accepted",
    fingerprint: "n1wR6djy98g.1fHOdRL1NbY",
  },
  {
    id: "catalog/permission-declared-twice",
    title: "The same permission declared twice",
    catalog: { permissions: ["report:read", "report:write", "report:read"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permission-uppercase",
    title: "A permission spelled with an uppercase letter",
    catalog: { permissions: ["Report:read"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permission-without-action",
    title: "A permission with no `:`",
    catalog: { permissions: ["report"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permission-three-parts",
    title: "A permission with two `:`",
    catalog: { permissions: ["report:read:all"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permission-leading-digit",
    title: "A resource that starts with a digit",
    catalog: { permissions: ["1report:read"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permission-token-too-long",
    title: "A resource of thirty-three characters",
    catalog: { permissions: ["abcdefghijklmnopqrstuvwxyz0123456:read"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permission-wildcard-declared",
    title: "A wildcard declared as a permission",
    catalog: { permissions: ["report:read", "report:*"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permission-star-star",
    title: "`*:*` declared as a permission",
    catalog: { permissions: ["*:*"] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/implication-to-undeclared",
    title: "An implication to a permission the catalog does not declare",
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:write": ["report:list"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/implication-from-undeclared",
    title: "An implication from a permission the catalog does not declare",
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:list": ["report:read"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/implication-to-wildcard",
    title: "An implication to a wildcard",
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:write": ["report:*"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/implication-from-wildcard",
    title: "An implication from a wildcard",
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:*": ["report:read"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/implication-two-cycle",
    title: "Two permissions that imply each other",
    catalog: {
      permissions: ["report:read", "report:write"],
      implies: { "report:write": ["report:read"], "report:read": ["report:write"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/implication-three-cycle",
    title: "A cycle of implications through three permissions",
    catalog: {
      permissions: ["report:list", "report:read", "report:write"],
      implies: {
        "report:write": ["report:read"],
        "report:read": ["report:list"],
        "report:list": ["report:write"],
      },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/structure-empty-object",
    title: "A structure that declares no level",
    catalog: { permissions: ["report:read"], places: {} },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/structure-empty-root",
    title: "A structure whose only parent lists no level",
    catalog: { permissions: ["report:read"], places: { "/": [] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/structure-parent-sits-nowhere",
    title: "A level under a level that itself sits nowhere",
    catalog: { permissions: ["report:read"], places: { "/": ["org"], "unit": ["team"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/structure-level-not-a-token",
    title: "A level spelled with an uppercase letter",
    catalog: { permissions: ["report:read"], places: { "/": ["Org"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/structure-parent-not-a-token",
    title: "A parent that is neither `/`, `*` nor a token",
    catalog: { permissions: ["report:read"], places: { "/": ["org"], "org unit": ["team"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-references-unknown-role",
    title: "A preset that names a role no preset declares, as a stored role would be",
    catalog: { permissions: ["report:read"], presets: { viewer: ["reader"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-excludes-unknown-role",
    title: "A preset that excludes a role no preset declares",
    catalog: {
      permissions: ["report:read", "report:write"],
      presets: { editor: ["report:*", "-auditor"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-cycle",
    title: "Two presets that reference each other",
    catalog: {
      permissions: ["report:read", "report:write"],
      presets: { viewer: ["report:read", "editor"], editor: ["report:write", "viewer"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-cycle-through-exclusion",
    title: "A cycle closed by an exclusion",
    catalog: {
      permissions: ["report:read", "report:write"],
      presets: { viewer: ["report:read", "-editor"], editor: ["report:write", "viewer"] },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-self-reference",
    title: "A preset that references itself",
    catalog: { permissions: ["report:read"], presets: { viewer: ["report:read", "viewer"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-unknown-permission",
    title: "A preset that names a permission the catalog does not declare",
    catalog: { permissions: ["report:read"], presets: { viewer: ["report:read", "billing:read"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-wildcard-matching-nothing",
    title: "A preset whose wildcard matches no declared permission",
    catalog: { permissions: ["report:read"], presets: { viewer: ["report:read", "invoice:*"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-star-star",
    title: "A preset entry spelled `*:*`",
    catalog: { permissions: ["report:read"], presets: { owner: ["*:*"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/preset-name-not-a-token",
    title: "A preset named with an uppercase letter",
    catalog: { permissions: ["report:read"], presets: { Viewer: ["report:read"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/unknown-member",
    title: "A member the model does not define",
    catalog: { permissions: ["report:read"], roles: { viewer: ["report:read"] } },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/manager-member",
    title: "A catalog that designates a manager permission, a member the model no longer defines",
    catalog: { permissions: ["access:manage", "report:read"], manager: "access:manage" },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/assigner-member",
    title:
      "A catalog that names the permission assigning a preset, a member the model no longer defines",
    catalog: {
      permissions: ["doc:write", "member:assign"],
      presets: { member: ["doc:write"] },
      assigner: { member: "member:assign" },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/manager-beside-every-member",
    title: "Every member the model defines, and a manager and an assigner beside them",
    catalog: {
      permissions: ["report:write", "report:read", "doc:read", "member:assign", "access:manage"],
      implies: { "report:write": ["report:read"] },
      presets: { viewer: ["*:read"], member: ["report:read"] },
      places: { "/": ["org"], "org": ["unit"] },
      manager: "access:manage",
      assigner: { member: "member:assign" },
    },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/not-an-object-null",
    title: "`null` in place of a catalog",
    catalog: null,
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/not-an-object-list",
    title: "A list of permissions in place of a catalog",
    catalog: ["report:read"],
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/not-an-object-string",
    title: "A string in place of a catalog",
    catalog: "report:read",
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permissions-not-a-list",
    title: "Permissions given as one string",
    catalog: { permissions: "report:read" },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/permissions-not-strings",
    title: "Permissions given as numbers",
    catalog: { permissions: [1, 2] },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
  {
    id: "catalog/places-true",
    title: "`places: true`, which is neither a structure nor `false`",
    catalog: { permissions: ["report:read"], places: true },
    expect: "ERR_AUTHZ_CATALOG_INVALID",
  },
];
