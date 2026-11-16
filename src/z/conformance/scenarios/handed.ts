import type { CatalogData } from "../../catalog.ts";
import type { Question } from "../engine.ts";
import type { HandStep, Scenario } from "../types.ts";
import { DAY, MONDAY, allow, assign, deny, exclude, hand } from "./_internal/steps.ts";

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

/** Posts in an application that declares it has no places. */
const notes: CatalogData = { permissions: ["post:read", "post:write"], places: false };

const annReads = allow("ann", "report:read", ACME);
const readsInUnit: Question = { permission: "report:read", place: U1 };
const readsPosts: Question = { permission: "post:read" };

/**
 * Statements an application hands over beside what a question reads (Section 7 of the model). A
 * question reads the statements at the keys of the chain of its target, compared byte by byte, and
 * of those the assignments and the ones whose value is a spelling it looks up. To find them it
 * reads the place of everything handed in: an absent place is the root, and a text is compared with
 * the keys of the chain. What gives it nothing to compare is refused as malformed: an item that is
 * not a statement in shape at all, and a statement whose place is present and is not text. A text
 * equal to no key of the chain is a statement elsewhere, whatever its spelling. Beyond its place,
 * what a question does not read is not checked, and issuing, which reads everything, refuses it.
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
  {
    id: "decision/deny-from-a-null-column",
    title:
      "A deny of reading read from a NULL place column gives Ann's question nothing to compare: it is refused, and so are her grants",
    proves: [],
    catalog: reports,
    steps: [
      refused(readsInUnit, { kind: "deny", subject: "ann", value: "report:read", place: null }),
    ],
  },
  {
    id: "decision/nothing-to-compare",
    title:
      "A row that is not a statement at all, or whose place is not text, gives Ann's question nothing to compare: refused wherever it sits in what is handed over, whatever the row says and whether it relates or not, and her grants too",
    proves: [],
    catalog: reports,
    steps: [
      refused(readsInUnit, null),
      refused(readsInUnit, "deny ann report:read"),
      refused(readsInUnit, ["deny", "ann", "report:read", ACME]),
      refused(readsInUnit, 7),
      refused(readsInUnit, { kind: "allow", subject: "ann", value: "report:write", place: null }),
      refused(readsInUnit, { kind: "deny", subject: "ann", value: "billing:read", place: null }),
      refused(readsInUnit, { kind: "assign", subject: "ann", value: "writer", place: 7 }),
      refused(readsInUnit, {
        kind: "deny",
        subject: "ann",
        value: "report:read",
        place: { org: "globex" },
      }),
      refused(readsInUnit, {
        kind: "exclude",
        subject: "ann",
        value: "legacy:export",
        place: ["org", "acme"],
      }),
      refused(readsInUnit, { kind: "deny", subject: "bob", value: "report:read", place: null }),
      refused(readsInUnit, {
        kind: "deny",
        subject: "ann",
        value: "report:read",
        place: null,
        expiresAt: MONDAY - DAY,
      }),
      refused(
        { permission: "report:read" },
        {
          kind: "deny",
          subject: "ann",
          value: "report:read",
          place: null,
        },
      ),
    ],
  },
  {
    id: "decision/root-absent-or-written",
    title: "A statement with no place and one at `/` are both at the root, and answer alike",
    proves: ["G2"],
    catalog: reports,
    steps: [
      atRoot(readsInUnit, [allow("ann", "report:read")], "allowed"),
      atRoot(readsInUnit, [allow("ann", "report:read", "/")], "allowed"),
      atRoot(readsInUnit, [allow("ann", "report:read"), deny("ann", "report:read", "/")], "denied"),
      atRoot(readsInUnit, [allow("ann", "report:read", "/"), deny("ann", "report:read")], "denied"),
      atRoot(
        readsInUnit,
        [allow("ann", "report:read"), exclude("ann", "report:read", "/")],
        "denied",
      ),
    ],
  },
  {
    id: "decision/root-absent-or-written-without-places",
    title:
      "In a notes app without places, a statement with no place and one at `/` are the same place and answer alike",
    proves: ["G2"],
    catalog: notes,
    steps: [
      atRoot(readsPosts, [allow("ann", "post:read")], "allowed"),
      atRoot(readsPosts, [allow("ann", "post:read", "/")], "allowed"),
      atRoot(readsPosts, [allow("ann", "post:read"), deny("ann", "post:read", "/")], "denied"),
      atRoot(readsPosts, [allow("ann", "post:read", "/"), deny("ann", "post:read")], "denied"),
      atRoot(readsPosts, [allow("ann", "post:read", "/"), exclude("ann", "post:read")], "denied"),
    ],
  },
];

/** Ann asks `question` of exactly `statements`, and grants issued from them answer alike. */
function atRoot(
  question: Question,
  statements: readonly unknown[],
  expect: HandStep["expect"],
): HandStep {
  return hand(MONDAY, "ann", statements, question, expect, { issuedAt: MONDAY });
}

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
