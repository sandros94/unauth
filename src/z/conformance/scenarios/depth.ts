import {
  DEPTH,
  IMPLIED,
  implicationChain,
  link,
  presetChain,
  step,
  storedChain,
  storedRing,
} from "../_internal/deep.ts";
import type { Scenario } from "../types.ts";
import { MONDAY, allow, ask, assign, deny } from "./_internal/steps.ts";

const ACME = "/org=acme";
const places = { "/": ["org"] };

/**
 * Roles and implications thousands deep: the model sets no limit, and resolution always
 * terminates (Section 7.1).
 */
export const depthScenarios: readonly Scenario[] = [
  {
    id: "roles/deep-stored-chain",
    title: `A chain of ${DEPTH} stored roles ends in reading reports: a subject assigned the first reads, from statements and grants alike`,
    proves: ["G1", "G8"],
    catalog: { permissions: ["report:read", "report:write"], places },
    roles: storedChain(DEPTH, "report:read"),
    statements: [assign("ann", link(0), ACME)],
    steps: [
      ask(MONDAY, { subject: "ann", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "ann", permission: "report:write", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
    ],
  },
  {
    id: "roles/deep-stored-ring",
    title: `A ring of ${DEPTH} stored roles written without validation: the subject assigned one gets nothing`,
    proves: ["G9"],
    catalog: { permissions: ["report:read"], places },
    roles: storedRing(DEPTH),
    statements: [assign("bob", link(0), ACME), allow("bob", "report:read", "/org=globex")],
    steps: [
      ask(MONDAY, { subject: "bob", permission: "report:read", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
    ],
  },
  {
    id: "roles/deep-preset-chain",
    title: `A catalog of ${DEPTH} presets, each built on the next, the last reading reports: the first gives reading`,
    proves: ["G1", "G8"],
    catalog: {
      permissions: ["report:read", "report:write"],
      presets: presetChain(DEPTH, "report:read"),
      places,
    },
    statements: [assign("cy", link(0), ACME)],
    steps: [
      ask(MONDAY, { subject: "cy", permission: "report:read", place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "cy", permission: "report:write", place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
    ],
  },
  {
    id: "decision/deep-implication-chain",
    title: `${IMPLIED} permissions each implying the next: an allow of the first answers the last, a deny of the last blocks the first`,
    proves: ["G3", "G8"],
    catalog: { ...implicationChain(IMPLIED), places },
    statements: [
      allow("dee", step(0), ACME),
      allow("eli", step(0), ACME),
      deny("eli", step(IMPLIED - 1), ACME),
    ],
    steps: [
      ask(MONDAY, { subject: "dee", permission: step(IMPLIED - 1), place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "eli", permission: step(0), place: ACME }, "denied", {
        issuedAt: MONDAY,
      }),
      ask(MONDAY, { subject: "dee", permission: step(0), place: ACME }, "allowed", {
        issuedAt: MONDAY,
      }),
    ],
  },
];
