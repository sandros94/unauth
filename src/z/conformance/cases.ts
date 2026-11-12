import { catalogCases } from "./cases/catalog.ts";
import { definitionCases } from "./cases/grants/definitions.ts";
import { divergedCases } from "./cases/grants/diverged.ts";
import { formCases } from "./cases/grants/form.ts";
import { printedCases } from "./cases/grants/printed.ts";
import { placeCases } from "./cases/place.ts";
import { roleCases } from "./cases/role.ts";
import { statementCases } from "./cases/statement.ts";
import { appendixScenarios } from "./scenarios/appendix.ts";
import { catalogScenarios } from "./scenarios/catalog.ts";
import { decisionScenarios } from "./scenarios/decision.ts";
import { depthScenarios } from "./scenarios/depth.ts";
import { grantsScenarios } from "./scenarios/grants.ts";
import { roleScenarios } from "./scenarios/roles.ts";
import type { Cases, GrantsCase, Scenario } from "./types.ts";

/**
 * Every scenario: decisions first, then roles, then grants, then grants read under another
 * catalog, then roles and implications thousands deep, then the model's Appendix A.
 */
export const scenarios: readonly Scenario[] = [
  ...decisionScenarios,
  ...roleScenarios,
  ...grantsScenarios,
  ...catalogScenarios,
  ...depthScenarios,
  ...appendixScenarios,
];

/**
 * Every grants object written by hand: those the model prints, the checks of their form, roles
 * read from their definitions, and grants read under another catalog.
 */
export const grantsCases: readonly GrantsCase[] = [
  ...printedCases,
  ...formCases,
  ...definitionCases,
  ...divergedCases,
];

/** Every case of the model, as `runConformance` takes them. */
export const cases: Cases = {
  scenarios,
  catalogCases,
  placeCases,
  grantsCases,
  statementCases,
  roleCases,
};
