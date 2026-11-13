import type { CatalogData } from "../../../catalog.ts";
import type { GrantsCase } from "../../types.ts";
import { ACME, MONDAY, readCase, reports, zoe } from "./_internal/model.ts";

/** `reports` while its writer preset only wrote: the presets segment differs. */
const writeOnly: CatalogData = { ...reports, presets: { writer: ["report:write"] } };

/** A copy of writer naming reading by its name, where a position belongs. */
const malformedCopy = {
  ...zoe,
  pm: ["report:read", "report:write"],
  ps: { writer: ["report:read", 1] },
  nt: { writer: { a: [[0]] } },
};

/** The stored analyst at the organisation, beside a permission table with a member in another spelling. */
const otherSpelling = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME],
  pm: ["report:read", "report:write", "Report:read"],
  nt: { analyst: { a: [[0]] } },
};

/**
 * Preset copies and definitions as a read meets them (Section 8.3 of the model): under the presets
 * of issue a copy of a declared preset is the catalog's own definition and is not read, under
 * other presets it is, and a resolved definition is checked down to the permissions it points at.
 */
export const copyCases: readonly GrantsCase[] = [
  readCase(
    "copy-malformed-under-presets-of-issue",
    "A malformed copy of writer under the presets it was issued under: the read takes the catalog's writer and answers, the whole is refused",
    {
      catalog: reports,
      grants: malformedCopy,
      expect: "allowed",
      whole: "ERR_AUTHZ_MALFORMED",
      diverged: null,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "copy-malformed-under-other-presets",
    "The same copy under presets changed since issue: writer is read from the copy, which is refused",
    {
      catalog: reports,
      issuedUnder: writeOnly,
      grants: malformedCopy,
      expect: "ERR_AUTHZ_MALFORMED",
      diverged: "ERR_AUTHZ_MALFORMED",
    },
    "report:write",
    ACME,
  ),
  readCase(
    "copy-of-undeclared-name-under-presets-of-issue",
    "A copy of auditor, which the catalog does not declare, under the presets of issue: read from the copy",
    {
      catalog: reports,
      grants: { ...zoe, pm: ["report:read"], ps: { auditor: [0] }, nt: { auditor: { a: [[0]] } } },
      expect: "allowed",
      diverged: null,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "definition-points-at-malformed-permission",
    "A stored analyst resolved at the organisation points at a member of the permission table in another spelling: refused",
    {
      catalog: reports,
      grants: { ...otherSpelling, sr: { analyst: [0, 2] } },
      expect: "ERR_AUTHZ_MALFORMED",
      diverged: null,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "malformed-permission-pointed-at-by-nothing",
    "The same member with nothing resolved pointing at it: the analyst answers, the whole is refused",
    {
      catalog: reports,
      grants: { ...otherSpelling, sr: { analyst: [0] } },
      expect: "allowed",
      whole: "ERR_AUTHZ_MALFORMED",
      diverged: null,
    },
    "report:read",
    ACME,
  ),
];
