import { authorityAppendixScenarios } from "./scenarios/authority-appendix.ts";
import { authorityChangeScenarios } from "./scenarios/authority-change.ts";
import { authorityGenesisScenarios } from "./scenarios/authority-genesis.ts";
import { authorityHoldingScenarios } from "./scenarios/authority-holding.ts";
import { authorityManagerScenarios } from "./scenarios/authority-managers.ts";
import { authorityRoleScenarios } from "./scenarios/authority-roles.ts";
import { authorityScenarios } from "./scenarios/authority.ts";
import { catalogCases } from "./scenarios/catalog-cases.ts";
import { decisionDepthScenarios } from "./scenarios/decision-depth.ts";
import { decisionExclusionScenarios } from "./scenarios/decision-exclusions.ts";
import { decisionInvalidScenarios } from "./scenarios/decision-invalid.ts";
import { decisionPlatformScenarios } from "./scenarios/decision-platforms.ts";
import { decisionStructureScenarios } from "./scenarios/decision-structure.ts";
import { decisionWorkspaceScenarios } from "./scenarios/decision-workspace.ts";
import { decisionScenarios } from "./scenarios/decision.ts";
import { grantsBundleScenarios } from "./scenarios/grants-bundles.ts";
import { grantsCases } from "./scenarios/grants-cases.ts";
import { grantsScenarios } from "./scenarios/grants.ts";
import { placeCases } from "./scenarios/place-cases.ts";
import { roleScenarios } from "./scenarios/roles.ts";
import type { Cases, Scenario } from "./types.ts";

/** Every scenario, decisions first, then grants, then who may change what. */
export const scenarios: readonly Scenario[] = [
  ...decisionScenarios,
  ...decisionDepthScenarios,
  ...decisionExclusionScenarios,
  ...decisionInvalidScenarios,
  ...decisionStructureScenarios,
  ...decisionPlatformScenarios,
  ...decisionWorkspaceScenarios,
  ...roleScenarios,
  ...grantsScenarios,
  ...grantsBundleScenarios,
  ...authorityScenarios,
  ...authorityGenesisScenarios,
  ...authorityManagerScenarios,
  ...authorityHoldingScenarios,
  ...authorityChangeScenarios,
  ...authorityRoleScenarios,
  ...authorityAppendixScenarios,
];

/** Every case of the model, as `validateEngine` takes them. */
export const cases: Cases = { scenarios, catalogCases, placeCases, grantsCases };
