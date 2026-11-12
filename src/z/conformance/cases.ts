import { catalogCases } from "./cases/catalog.ts";
import { grantsCases } from "./cases/grants.ts";
import { placeCases } from "./cases/place.ts";
import { roleCases } from "./cases/role.ts";
import { statementCases } from "./cases/statement.ts";
import { appendixScenarios } from "./scenarios/appendix.ts";
import { decisionScenarios } from "./scenarios/decision.ts";
import { grantsScenarios } from "./scenarios/grants.ts";
import { roleScenarios } from "./scenarios/roles.ts";
import type { Cases, Scenario } from "./types.ts";

/** Every scenario, decisions first, then roles, then grants, then the model's Appendix A. */
export const scenarios: readonly Scenario[] = [
  ...decisionScenarios,
  ...roleScenarios,
  ...grantsScenarios,
  ...appendixScenarios,
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
