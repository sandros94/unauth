import type { CatalogData } from "../../../catalog.ts";
import type { GrantsCase } from "../../types.ts";
import { ACME, DAY, MONDAY, diverged, readCase, reports, tabled, zoe } from "./_internal/model.ts";

/** `reports` with billing beside: a permission the question of reading reports never looks up. */
const ledger: CatalogData = { ...reports, permissions: ["billing:read", ...reports.permissions] };

/** `ledger` while its writer preset only wrote: the presets segment differs. */
const earlier: CatalogData = { ...ledger, presets: { writer: ["report:write"] } };

/** A permission table with a permission in another spelling at a position nothing names. */
const spelledOtherwise = { ...tabled, pm: ["report:read", "report:write", "Billing:read"] };

/** A stored auditor naming billing by its name, assigned at another organisation only. */
const auditorElsewhere = {
  ...tabled,
  pl: [ACME, "/org=globex"],
  sr: { analyst: [0], auditor: ["billing:read"] },
  nt: { ...tabled.nt, auditor: { a: [[1]] } },
};

/**
 * Grants malformed only where the question of reading reports at the organisation does not look,
 * one for each kind of check of Section 8.4 a read can leave aside: the read answers from what it
 * reads, validating the whole refuses. Under another catalog `diverged` reads the permission, preset
 * and stored role tables whole, and the names of the entries in grants with no permission table,
 * and a read with it.
 */
export const unreadCases: readonly GrantsCase[] = [
  unread(
    "place-table-of-another-type",
    "Every item at the root beside a place table written as one key: no item read names a place",
    { ...zoe, pl: ACME, nt: { "report:*": { a: [[]] }, "report:write": { x: [[]] } } },
  ),
  unread(
    "place-key-in-another-spelling",
    "A deny of billing at a place written in lowercase hexadecimal: no item read names it",
    { ...zoe, pl: [ACME, "/org=caf%c3%a9"], nt: { ...zoe.nt, "billing:read": { d: [[1]] } } },
  ),
  unread("root-in-place-table", "The root written in the place table at a position no item names", {
    ...zoe,
    pl: [ACME, "/"],
  }),
  unread(
    "permission-table-entry",
    "A permission spelled with an uppercase letter at a position of the permission table nothing names",
    spelledOtherwise,
  ),
  unread(
    "definition-of-a-role-elsewhere",
    "A stored auditor naming billing by its name, assigned only at another organisation: never resolved here",
    auditorElsewhere,
  ),
  unread(
    "definition-of-a-role-ended",
    "A stored auditor excluding billing in another spelling, assigned here until yesterday: never resolved",
    {
      ...tabled,
      sr: { analyst: [0], auditor: [0, "-Billing:read"] },
      nt: { ...tabled.nt, auditor: { a: [[0, MONDAY + DAY]] } },
    },
    MONDAY + 2 * DAY,
  ),
  unread("entry-member", "An entry of billing holding a member other than a, d and x", {
    ...zoe,
    nt: { ...zoe.nt, "billing:read": { a: [[0]], z: [[0]] } },
  }),
  unread("item-place-index", "An item of billing naming a place the table does not hold", {
    ...zoe,
    nt: { ...zoe.nt, "billing:read": { a: [[5]] } },
  }),
  readCase(
    "unread-entry-name-under-another-catalog",
    "Under a catalog whose presets changed, an entry naming writing by its name beside a permission table: diverged reads the tables, not the entries, so the read answers and tells the segment",
    {
      catalog: ledger,
      issuedUnder: earlier,
      grants: { ...tabled, nt: { ...tabled.nt, "report:write": { d: [[0]] } } },
      expect: "allowed",
      whole: "ERR_AUTHZ_MALFORMED",
      diverged: diverged(["presets"]),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "unread-entry-name-without-table-under-another-catalog",
    "Under a catalog whose presets changed, grants with no permission table hold a deny under another spelling of reading: telling what diverged reads the names of the entries, so the read is refused",
    {
      catalog: ledger,
      issuedUnder: earlier,
      grants: { ...zoe, nt: { ...zoe.nt, "Report:read": { d: [[0]] } } },
      expect: "ERR_AUTHZ_MALFORMED",
      diverged: "ERR_AUTHZ_MALFORMED",
    },
    "report:read",
    ACME,
  ),
  ...(
    [
      ["permission-table-entry", "the permission table", spelledOtherwise],
      ["definition-of-a-role-elsewhere", "the stored role table", auditorElsewhere],
    ] as const
  ).map(([id, table, grants]) =>
    readCase(
      `unread-${id}-under-another-catalog`,
      `The same grants under a catalog whose presets changed: telling what diverged reads ${table} whole, so the read is refused`,
      {
        catalog: ledger,
        issuedUnder: earlier,
        grants,
        expect: "ERR_AUTHZ_MALFORMED",
        diverged: "ERR_AUTHZ_MALFORMED",
      },
      "report:read",
      ACME,
    ),
  ),
];

function unread(id: string, title: string, grants: unknown, at = MONDAY): GrantsCase {
  return readCase(
    `unread-${id}`,
    `${title}: the read answers, the whole is refused`,
    {
      catalog: ledger,
      grants,
      expect: "allowed",
      whole: "ERR_AUTHZ_MALFORMED",
      diverged: null,
      at,
    },
    "report:read",
    ACME,
  );
}
