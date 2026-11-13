import type { CatalogData } from "../../../catalog.ts";
import type { GrantsCase } from "../../types.ts";
import {
  ACME,
  DAY,
  MONDAY,
  ARCHIVES,
  diverged,
  edCopies,
  flat,
  readCase,
  reports,
  sue,
  zoe,
} from "./_internal/model.ts";

const THURSDAY = MONDAY + 3 * DAY;
const SATURDAY = MONDAY + 5 * DAY;

/** `reports` with no implication. */
const unimplied: CatalogData = {
  permissions: reports.permissions,
  presets: reports.presets,
  places: reports.places,
};

/** `reports` before exporting left it. */
const withExport: CatalogData = {
  ...reports,
  permissions: ["report:export", "report:read", "report:write"],
};

/** `reports` while its writer preset only wrote. */
const writeOnly: CatalogData = { ...reports, presets: { writer: ["report:write"] } };

/** `reports` once its writer preset only reads. */
const readOnly: CatalogData = { ...reports, presets: { writer: ["report:read"] } };

/** `reports` while it declared a legacy permission and its writer preset only read. */
const legacy: CatalogData = {
  ...reports,
  permissions: ["legacy:export", "report:read", "report:write"],
  presets: { writer: ["legacy:export", "report:read"] },
};

/**
 * Grants written by hand, read under a catalog other than the one they were issued under: what
 * the read answers, and what it tells has diverged.
 */
export const divergedCases: readonly GrantsCase[] = [
  readCase(
    "by-name-permissions-changed",
    "Sue's grants carry writer by name and only a permission left the catalog since: read, the first segment told",
    {
      catalog: reports,
      issuedUnder: withExport,
      grants: sue,
      expect: "allowed",
      at: THURSDAY,
      diverged: diverged(["permissions"]),
    },
    "report:write",
    ARCHIVES,
  ),
  readCase(
    "by-name-presets-changed",
    "Sue's grants carry writer by name and the presets changed since: read, the second segment told and no role, since none is held as a copy",
    {
      catalog: reports,
      issuedUnder: writeOnly,
      grants: sue,
      expect: "allowed",
      at: THURSDAY,
      diverged: diverged(["presets"]),
    },
    "report:write",
    ARCHIVES,
  ),
  readCase(
    "by-name-preset-means-what-the-catalog-says",
    "Writer comes to only read: on Saturday, her own allow ended, Sue's writer by name no longer writes at the organisation",
    {
      catalog: readOnly,
      issuedUnder: reports,
      grants: sue,
      expect: "denied",
      at: SATURDAY,
      diverged: diverged(["presets"]),
    },
    "report:write",
    ACME,
  ),
  readCase(
    "by-name-preset-still-reads",
    "The same writer by name still reads at the organisation",
    { catalog: readOnly, issuedUnder: reports, grants: sue, expect: "allowed", at: SATURDAY },
    "report:read",
    ACME,
  ),
  readCase(
    "no-preset-presets-changed",
    "Zoe's grants name no preset and the presets changed since: read, the second segment told",
    {
      catalog: reports,
      issuedUnder: writeOnly,
      grants: zoe,
      expect: "allowed",
      diverged: diverged(["presets"]),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "copy-read-from-the-copy",
    "A copy of writer from when it only wrote: the read takes the copy, not the catalog's writer, and names it diverged",
    {
      catalog: reports,
      issuedUnder: writeOnly,
      grants: { ...zoe, pm: ["report:write"], ps: { writer: [0] }, nt: { writer: { a: [[0]] } } },
      expect: "allowed",
      diverged: diverged(["presets"], { presets: ["writer"] }),
    },
    "report:write",
    ACME,
  ),
  readCase(
    "copy-gives-no-more-than-it-held",
    "The same copy, under a catalog with no implication whose writer reads too: the copy does not give reading",
    {
      catalog: unimplied,
      issuedUnder: { ...unimplied, presets: { writer: ["report:write"] } },
      grants: { ...zoe, pm: ["report:write"], ps: { writer: [0] }, nt: { writer: { a: [[0]] } } },
      expect: "denied",
      diverged: diverged(["presets"], { presets: ["writer"] }),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "copy-names-undeclared-permission",
    "A copy of writer naming a legacy permission the catalog dropped: read from the copy, both the copy and the permission told",
    {
      catalog: reports,
      issuedUnder: legacy,
      grants: {
        ...zoe,
        pm: ["legacy:export", "report:read"],
        ps: { writer: [0, 1] },
        nt: { writer: { a: [[0]] } },
      },
      expect: "allowed",
      diverged: diverged(["permissions", "presets"], {
        permissions: ["legacy:export"],
        presets: ["writer"],
      }),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "entries-name-undeclared-permissions",
    "Entries naming two permissions the catalog dropped, by name: read, both listed in byte order",
    {
      catalog: reports,
      issuedUnder: {
        ...legacy,
        permissions: ["legacy:export", "legacy:audit", "report:read", "report:write"],
      },
      grants: {
        ...zoe,
        nt: { ...zoe.nt, "legacy:export": { a: [[0]] }, "legacy:audit": { d: [[0]] } },
      },
      expect: "allowed",
      diverged: diverged(["permissions", "presets"], {
        permissions: ["legacy:audit", "legacy:export"],
      }),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "copy-in-another-order",
    "Ed's editor copy lists its entries in another order than the catalog: only the viewer that changed is diverged",
    {
      catalog: { ...flat, presets: { viewer: ["post:read"], editor: ["viewer", "post:write"] } },
      issuedUnder: flat,
      grants: { ...edCopies, ps: { editor: [0, "viewer"], viewer: ["*:read"] } },
      expect: "allowed",
      at: MONDAY + DAY,
      diverged: diverged(["presets"], { presets: ["viewer"] }),
    },
    "post:write",
  ),
  readCase(
    "copy-with-a-repeated-entry",
    "Ed's editor copy names viewer twice: each entry is taken once, so only the viewer that changed is diverged",
    {
      catalog: { ...flat, presets: { viewer: ["post:read"], editor: ["viewer", "post:write"] } },
      issuedUnder: flat,
      grants: { ...edCopies, ps: { editor: ["viewer", 0, "viewer"], viewer: ["*:read"] } },
      expect: "allowed",
      at: MONDAY + DAY,
      diverged: diverged(["presets"], { presets: ["viewer"] }),
    },
    "post:write",
  ),
  readCase(
    "pattern-matching-nothing-never-listed",
    "Invoices left the catalog: the deny of paying one is listed, the allow of every invoice permission, a pattern, is not",
    {
      catalog: reports,
      issuedUnder: { ...reports, permissions: ["invoice:pay", "report:read", "report:write"] },
      grants: { ...zoe, nt: { ...zoe.nt, "invoice:*": { a: [[0]] }, "invoice:pay": { d: [[0]] } } },
      expect: "allowed",
      diverged: diverged(["permissions"], { permissions: ["invoice:pay"] }),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "same-catalog-undeclared-permission-tells-nothing",
    "Grants of this very catalog naming a permission it does not declare: both segments are its own, so nothing has diverged",
    {
      catalog: reports,
      grants: { ...zoe, nt: { ...zoe.nt, "billing:read": { a: [[0]] } } },
      expect: "allowed",
      diverged: null,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "same-catalog-copy-differs-tells-nothing",
    "Grants of this very catalog holding a writer copy that only writes, unlike the catalog's: the presets are those of issue, so the read takes the catalog's writer, which reads, and nothing has diverged",
    {
      catalog: { ...unimplied },
      grants: { ...zoe, pm: ["report:write"], ps: { writer: [0] }, nt: { writer: { a: [[0]] } } },
      expect: "allowed",
      diverged: null,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "sets-union",
    "A set with a diverged copy naming a dropped permission and a set naming another, read together: the read tells the union",
    {
      catalog: reports,
      issuedUnder: legacy,
      grants: [
        {
          ...zoe,
          pm: ["legacy:export", "report:read"],
          ps: { writer: [0, 1] },
          nt: { writer: { a: [[0]] } },
        },
        { ...zoe, nt: { "report:export": { a: [[0]] }, "report:read": { a: [[0]] } } },
      ],
      expect: "allowed",
      diverged: diverged(["permissions", "presets"], {
        permissions: ["legacy:export", "report:export"],
        presets: ["writer"],
      }),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "sets-one-of-another-catalog",
    "A set of this catalog and a set of another read together: what diverged is told, from the other",
    {
      catalog: reports,
      grants: [zoe, { ...zoe, ct: "Az09-_az09A.Zz-_09azAZ0" }],
      expect: "allowed",
      diverged: diverged(["permissions", "presets"]),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "sets-all-of-this-catalog",
    "Two sets of this catalog read together: nothing has diverged",
    { catalog: reports, grants: [zoe, { ...zoe, bs: [ACME] }], expect: "allowed", diverged: null },
    "report:read",
    ACME,
  ),
];
