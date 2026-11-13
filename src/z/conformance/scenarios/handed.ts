import type { CatalogData } from "../../catalog.ts";
import type { Question } from "../engine.ts";
import type { HandStep, Scenario } from "../types.ts";
import { MONDAY, allow, assign, deny, exclude, hand } from "./_internal/steps.ts";

const ACME = "/org=acme";
const U1 = "/org=acme/unit=u1";
const GLOBEX = "/org=globex";
/** Café, its é written as one character, as the application brings every name. */
const CAFE = "/org=caf%C3%A9";
/** Café, its é written as an e and a combining accent: canonical, and another place. */
const CAFE_DECOMPOSED = "/org=cafe%CC%81";

const reports: CatalogData = {
  permissions: ["billing:read", "report:read", "report:write"],
  implies: { "report:write": ["report:read"] },
  presets: { writer: ["report:read", "report:write"] },
  places: { "/": ["org"], "org": ["unit"] },
};

const annReads = allow("ann", "report:read", ACME);
const readsInUnit: Question = { permission: "report:read", place: U1 };

/**
 * Statements an application hands over beside what a question reads (Section 7 of the model): a
 * question reads those at the keys of its chain, compared byte by byte, and of those the
 * assignments and the ones whose value it looks up. What it does not read is not checked, and
 * issuing, which reads everything, refuses it.
 */
export const handedScenarios: readonly Scenario[] = [
  {
    id: "decision/malformed-off-the-chain",
    title:
      "Rows left malformed by an old import sit off the chain of Ann's question: she is answered as if they were not there, and issuing her grants is refused",
    proves: ["G5"],
    catalog: reports,
    steps: [
      answered(deny("ann", "report:read", `${GLOBEX}/`)),
      answered(deny("ann", "report:read", `${ACME}/`)),
      answered({
        kind: "deny",
        subject: "ann",
        value: "report:read",
        place: GLOBEX,
        expiresAt: "friday",
      }),
      answered(null),
      answered("deny ann report:read"),
    ],
  },
  {
    id: "decision/malformed-on-the-chain-unread",
    title:
      "Rows on the chain of Ann's question whose value it never looks up are not checked: she reads, and issuing her grants is refused",
    proves: ["G5"],
    catalog: reports,
    steps: [
      answered(deny("ann", "Report:read", ACME)),
      answered(deny("ann", "*:*", ACME)),
      answered(exclude("ann", "-report:read", ACME)),
      answered({
        kind: "deny",
        subject: "ann",
        value: "billing:read",
        place: ACME,
        expiresAt: MONDAY * 1000,
      }),
    ],
  },
  {
    id: "decision/malformed-and-read",
    title:
      "A row the question reads holds a time or a role name in another form: refused, asked of the statements and issued alike",
    proves: [],
    catalog: reports,
    steps: [
      refused(readsInUnit, {
        kind: "deny",
        subject: "ann",
        value: "report:read",
        place: ACME,
        expiresAt: MONDAY * 1000,
      }),
      refused(readsInUnit, {
        kind: "allow",
        subject: "ann",
        value: "report:write",
        expiresAt: "friday",
      }),
      refused(readsInUnit, {
        kind: "exclude",
        subject: "ann",
        value: "*:read",
        place: U1,
        expiresAt: MONDAY + 0.5,
      }),
      refused(readsInUnit, assign("ann", "Writer", ACME)),
      refused(readsInUnit, {
        kind: "assign",
        subject: "ann",
        value: "writer",
        place: U1,
        expiresAt: -1,
      }),
      refused({ permission: "billing:read", place: U1 }, assign("ann", "Writer", ACME)),
    ],
  },
  {
    id: "decision/deny-under-another-spelling",
    title:
      "A deny of reading is written at Café spelled another way: it is at no place Ann asks about, and blocks nothing, silently",
    proves: ["G5", "G2"],
    catalog: reports,
    steps: [
      hand(
        MONDAY,
        "ann",
        [allow("ann", "report:read", CAFE), deny("ann", "report:read", CAFE)],
        { permission: "report:read", place: `${CAFE}/unit=u1` },
        "denied",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [allow("ann", "report:read", CAFE), deny("ann", "report:read", CAFE_DECOMPOSED)],
        { permission: "report:read", place: `${CAFE}/unit=u1` },
        "allowed",
        { issuedAt: MONDAY },
      ),
      hand(
        MONDAY,
        "ann",
        [allow("ann", "report:read", CAFE), deny("ann", "report:read", "/org=caf%c3%a9")],
        { permission: "report:read", place: `${CAFE}/unit=u1` },
        "allowed",
        { issuedAt: MONDAY, fromGrants: "ERR_AUTHZ_MALFORMED" },
      ),
    ],
  },
];

/** Ann reads in her unit beside `row`, and issuing from the same is refused. */
function answered(row: unknown): HandStep {
  return hand(MONDAY, "ann", [annReads, row], readsInUnit, "allowed", {
    issuedAt: MONDAY,
    fromGrants: "ERR_AUTHZ_MALFORMED",
  });
}

/** `question` beside `row` is refused as malformed, and so is issuing from the same. */
function refused(question: Question, row: unknown): HandStep {
  return hand(MONDAY, "ann", [annReads, row], question, "ERR_AUTHZ_MALFORMED", {
    issuedAt: MONDAY,
  });
}
