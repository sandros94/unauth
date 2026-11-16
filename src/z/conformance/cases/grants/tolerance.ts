import type { CatalogData } from "../../../catalog.ts";
import type { GrantsCase } from "../../types.ts";
import {
  ACME,
  DAY,
  FRIDAY_MIDNIGHT,
  MONDAY,
  type Written,
  diverged,
  readCase,
  reports,
  zoe,
} from "./_internal/model.ts";

const GLOBEX = "/org=globex";
const MINUTE = 60;
/** Five minutes, a clock tolerance an application might give a browser. */
const FIVE_MINUTES = 300;

/** `reports` before exporting left it. */
const withExport: CatalogData = {
  ...reports,
  permissions: ["report:export", "report:read", "report:write"],
};

/** Kim is allowed every report action at the organisation, and suspended from writing until Friday. */
const suspended: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME],
  nt: { "report:*": { a: [[0]] }, "report:write": { d: [[0, FRIDAY_MIDNIGHT]] } },
};

/** Sue's own allow of writing at the organisation, until Friday. */
const writesUntilFriday: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY,
  pl: [ACME],
  nt: { "report:write": { a: [[0, FRIDAY_MIDNIGHT]] } },
};

/** Zoe, allowed every report action and kept from writing by an exclusion of her own until Friday. */
const excludedUntilFriday: Written = {
  ...zoe,
  nt: { "report:*": { a: [[0]] }, "report:write": { x: [[0, FRIDAY_MIDNIGHT]] } },
};

/** Zoe's grants for the organisation alone. */
const acmeNow: Written = { ...zoe, bs: [ACME] };

/** A set for another organisation, issued a minute after `acmeNow`. */
const globexLater: Written = {
  v: "1",
  ct: "$ct",
  at: MONDAY + MINUTE,
  bs: [GLOBEX],
  pl: [GLOBEX],
  nt: { "report:read": { a: [[0]] } },
};

/**
 * Grants read under the clock tolerance the application gives a read, as `clockTolerance` (Section
 * 8.3 of the model), since the clock that reads grants is rarely the one that issued them. Under a
 * tolerance the grants are refused as issued in the future only when the time of the read plus
 * the tolerance is earlier than their issue, and an end counts that much later, for a deny and an
 * exclusion as for an allow. With none given, every time is exact.
 */
export const toleranceCases: readonly GrantsCase[] = [
  readCase(
    "tolerance-covers-five-seconds-behind",
    "A browser whose clock runs five seconds behind reads Zoe's grants with a clock tolerance of five seconds",
    {
      catalog: reports,
      grants: zoe,
      expect: "allowed",
      at: MONDAY - 5,
      clockTolerance: 5,
      diverged: null,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "tolerance-exceeded-by-one-second",
    "A browser six seconds behind, with a clock tolerance of five: issued in the future, and validating them whole refuses too",
    {
      catalog: reports,
      grants: zoe,
      expect: "ERR_AUTHZ_GRANTS_FUTURE",
      at: MONDAY - 6,
      clockTolerance: 5,
      diverged: "ERR_AUTHZ_GRANTS_FUTURE",
    },
    "report:read",
    ACME,
  ),
  readCase(
    "tolerance-exactly-at-the-bound",
    "A clock thirty seconds behind with a clock tolerance of thirty: the time of the read plus the tolerance is the time of issue, read",
    {
      catalog: reports,
      grants: zoe,
      expect: "allowed",
      at: MONDAY - 30,
      clockTolerance: 30,
      diverged: null,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "tolerance-under-another-catalog",
    "Grants issued while exporting was declared, read ten seconds early within the clock tolerance: answered, and the first segment told with and without a question",
    {
      catalog: reports,
      issuedUnder: withExport,
      grants: zoe,
      expect: "allowed",
      at: MONDAY - 10,
      clockTolerance: 30,
      diverged: diverged(["permissions"]),
    },
    "report:read",
    ACME,
  ),
  readCase(
    "tolerance-under-another-catalog-exceeded",
    "The same grants read thirty-one seconds early with a clock tolerance of thirty: refused, by a read and by diverged alone",
    {
      catalog: reports,
      issuedUnder: withExport,
      grants: zoe,
      expect: "ERR_AUTHZ_GRANTS_FUTURE",
      at: MONDAY - 31,
      clockTolerance: 30,
      diverged: "ERR_AUTHZ_GRANTS_FUTURE",
    },
    "report:read",
    ACME,
  ),
  readCase(
    "tolerance-every-set-read-together",
    "Two sets read together, one issued a minute later for another organisation, half a minute early with a clock tolerance of thirty seconds: read",
    {
      catalog: reports,
      grants: [acmeNow, globexLater],
      expect: "allowed",
      at: MONDAY + 30,
      clockTolerance: 30,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "tolerance-one-set-read-too-early",
    "The same two sets with a clock tolerance of twenty-nine seconds: the later set is issued in the future, and the read refuses though it does not cover the target",
    {
      catalog: reports,
      grants: [acmeNow, globexLater],
      expect: "ERR_AUTHZ_GRANTS_FUTURE",
      at: MONDAY + 30,
      clockTolerance: 29,
    },
    "report:read",
    ACME,
  ),
  readCase(
    "tolerance-keeps-an-allow-that-just-ended",
    "Sue's allow ended a second ago and her clock may run five minutes ahead: under that clock tolerance it still counts",
    {
      catalog: reports,
      grants: writesUntilFriday,
      expect: "allowed",
      at: FRIDAY_MIDNIGHT + 1,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-allow-inside-the-bound",
    "Sue's allow ended four minutes and fifty-nine seconds ago, under a clock tolerance of five minutes: it still counts",
    {
      catalog: reports,
      grants: writesUntilFriday,
      expect: "allowed",
      at: FRIDAY_MIDNIGHT + FIVE_MINUTES - 1,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-allow-at-the-bound",
    "Sue's allow ended exactly five minutes ago, under a clock tolerance of five minutes: its end plus the tolerance is the time of the read, no longer live",
    {
      catalog: reports,
      grants: writesUntilFriday,
      expect: "denied",
      at: FRIDAY_MIDNIGHT + FIVE_MINUTES,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-allow-that-ends-soon",
    "Sue's allow ends in a second, under a clock tolerance of a day: it counts",
    {
      catalog: reports,
      grants: writesUntilFriday,
      expect: "allowed",
      at: FRIDAY_MIDNIGHT - 1,
      clockTolerance: DAY,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "no-tolerance-ends-an-allow",
    "Sue's allow ended a second ago and no clock tolerance is given: it no longer counts",
    {
      catalog: reports,
      grants: writesUntilFriday,
      expect: "denied",
      at: FRIDAY_MIDNIGHT + 1,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-keeps-a-deny-that-just-ended",
    "Kim's suspension from writing ended a second ago, under a clock tolerance of five minutes: it still blocks, as an allow would still give",
    {
      catalog: reports,
      grants: suspended,
      expect: "denied",
      at: FRIDAY_MIDNIGHT + 1,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-deny-at-the-bound",
    "Kim's suspension ended exactly five minutes ago, under a clock tolerance of five minutes: lifted, she writes",
    {
      catalog: reports,
      grants: suspended,
      expect: "allowed",
      at: FRIDAY_MIDNIGHT + FIVE_MINUTES,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-deny-that-ends-soon",
    "Kim's suspension ends in a second, under a clock tolerance of five minutes: it blocks",
    {
      catalog: reports,
      grants: suspended,
      expect: "denied",
      at: FRIDAY_MIDNIGHT - 1,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "no-tolerance-lifts-a-deny",
    "Kim's suspension ended a second ago and no clock tolerance is given: she writes",
    {
      catalog: reports,
      grants: suspended,
      expect: "allowed",
      at: FRIDAY_MIDNIGHT + 1,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-keeps-an-exclusion-that-just-ended",
    "Zoe's own exclusion from writing ended a second ago, under a clock tolerance of five minutes: it still takes writing out",
    {
      catalog: reports,
      grants: excludedUntilFriday,
      expect: "denied",
      at: FRIDAY_MIDNIGHT + 1,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "tolerance-exclusion-at-the-bound",
    "Zoe's exclusion ended exactly five minutes ago, under a clock tolerance of five minutes: lifted, she writes",
    {
      catalog: reports,
      grants: excludedUntilFriday,
      expect: "allowed",
      at: FRIDAY_MIDNIGHT + FIVE_MINUTES,
      clockTolerance: FIVE_MINUTES,
    },
    "report:write",
    ACME,
  ),
  readCase(
    "no-tolerance-lifts-an-exclusion",
    "Zoe's exclusion ended a second ago and no clock tolerance is given: she writes",
    {
      catalog: reports,
      grants: excludedUntilFriday,
      expect: "allowed",
      at: FRIDAY_MIDNIGHT + 1,
    },
    "report:write",
    ACME,
  ),
];
