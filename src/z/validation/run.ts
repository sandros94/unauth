import type { Catalog } from "../catalog.ts";
import { clock, isRecord, roleKey, sameData } from "./_internal/data.ts";
import {
  type Context,
  attempt,
  expectOutcome,
  fail,
  failureOf,
  untouched,
} from "./_internal/outcome.ts";
import { runChange, runGenesis } from "./_internal/scenario-change.ts";
import {
  type ScenarioState,
  runAsk,
  runIssue,
  runRead,
  runWrite,
  storeStatement,
} from "./_internal/scenario.ts";
import type {
  Cases,
  CatalogCase,
  Engine,
  GrantsCase,
  PlaceCase,
  Scenario,
  ValidationReport,
} from "./types.ts";

/**
 * Runs a scenario against an engine, step by step, over the statements and stored roles it keeps.
 * Every call that takes statements is made twice, given everything stored and given only what the
 * call needs, and both answers must be the one the step expects.
 *
 * @throws an `Error` whose `cause` is a `ValidationFailure` at the first wrong answer.
 */
export function runScenario(engine: Engine, scenario: Scenario): void {
  const state: ScenarioState = {
    catalog: defineFor(engine, scenario.catalog, { id: scenario.id }),
    statements: new Map(),
    roles: new Map(),
    grants: new Map(),
  };
  for (const statement of scenario.statements ?? []) storeStatement(state, statement);
  for (const role of scenario.roles ?? []) state.roles.set(roleKey(role), structuredClone(role));
  for (const [index, step] of scenario.steps.entries()) {
    const context: Context = { id: scenario.id, step: index };
    switch (step.step) {
      case "ask": {
        runAsk(engine, state, step, context);
        break;
      }
      case "issue": {
        runIssue(engine, state, step, context);
        break;
      }
      case "read": {
        runRead(engine, state, step, context);
        break;
      }
      case "change": {
        runChange(engine, state, step, context);
        break;
      }
      case "genesis": {
        runGenesis(engine, state, step, context);
        break;
      }
      case "write": {
        runWrite(state, step);
        break;
      }
    }
  }
}

/**
 * Checks that an engine accepts or refuses a catalog, and computes the fingerprint given.
 *
 * @throws an `Error` whose `cause` is a `ValidationFailure` on a wrong answer.
 */
export function runCatalogCase(engine: Engine, catalogCase: CatalogCase): void {
  const context: Context = { id: catalogCase.id };
  const loose: LooseEngine = engine;
  const result = untouched(context, catalogCase.catalog, (data) => loose.defineCatalog(data));
  const received = result.ok ? "accepted" : result.code;
  if (received !== catalogCase.expect) fail(context, catalogCase.expect, received);
  if (result.ok && catalogCase.fingerprint !== undefined) {
    const fingerprint: unknown = isRecord(result.value) ? result.value.fingerprint : undefined;
    if (fingerprint !== catalogCase.fingerprint) {
      fail(context, { fingerprint: catalogCase.fingerprint }, { fingerprint });
    }
  }
}

/**
 * Checks what an engine makes of a key: its chain and range, or a refusal as malformed.
 *
 * @throws an `Error` whose `cause` is a `ValidationFailure` on a wrong answer.
 */
export function runPlaceCase(engine: Engine, placeCase: PlaceCase): void {
  const context: Context = { id: placeCase.id };
  const chain = attempt(() => engine.placeChain(placeCase.key));
  const range = attempt(() => engine.placeRange(placeCase.key));
  if (placeCase.expect === "ERR_AUTHZ_MALFORMED") {
    for (const [name, result] of [
      ["placeChain", chain],
      ["placeRange", range],
    ] as const) {
      const received = result.ok ? result.value : result.code;
      if (received !== placeCase.expect)
        fail(context, { [name]: placeCase.expect }, { [name]: received });
    }
    return;
  }
  if (!chain.ok)
    fail(context, { placeChain: placeCase.chain ?? "a chain" }, { placeChain: chain.code });
  if (!range.ok)
    fail(context, { placeRange: placeCase.range ?? "a range" }, { placeRange: range.code });
  if (placeCase.chain !== undefined && !sameData(chain.value, placeCase.chain)) {
    fail(context, { placeChain: placeCase.chain }, { placeChain: chain.value });
  }
  if (placeCase.range !== undefined && !sameData(range.value, placeCase.range)) {
    fail(context, { placeRange: placeCase.range }, { placeRange: range.value });
  }
}

/**
 * Reads grants written by hand, its `"$ct"` replaced with the catalog's fingerprint.
 *
 * @throws an `Error` whose `cause` is a `ValidationFailure` on a wrong answer.
 */
export function runGrantsCase(engine: Engine, grantsCase: GrantsCase): void {
  const context: Context = { id: grantsCase.id };
  const catalog = defineFor(engine, grantsCase.catalog, context);
  const grants: unknown = structuredClone(grantsCase.grants);
  if (isRecord(grants) && grants.ct === "$ct") grants.ct = catalog.fingerprint;
  const now = clock(grantsCase.at);
  const result = untouched(context, { grants, question: grantsCase.question }, (input) =>
    engine.readGrants(catalog, input.grants, input.question, { now }),
  );
  expectOutcome(context, grantsCase.expect, result);
}

/**
 * Runs every case and reports which passed and which answered otherwise. Never throws for a wrong
 * answer.
 */
export function validateEngine(engine: Engine, cases: Cases): ValidationReport {
  const report: ValidationReport = { passed: [], failed: [] };
  const run = (id: string, check: () => void): void => {
    try {
      check();
      report.passed.push(id);
    } catch (error) {
      report.failed.push(failureOf(id, error));
    }
  };
  for (const scenario of cases.scenarios) run(scenario.id, () => runScenario(engine, scenario));
  for (const item of cases.catalogCases) run(item.id, () => runCatalogCase(engine, item));
  for (const item of cases.placeCases) run(item.id, () => runPlaceCase(engine, item));
  for (const item of cases.grantsCases) run(item.id, () => runGrantsCase(engine, item));
  return report;
}

interface LooseEngine {
  defineCatalog(data: unknown): Catalog;
}

function defineFor(engine: Engine, data: Scenario["catalog"], context: Context): Catalog {
  const result = untouched(context, data, (copy) => engine.defineCatalog(copy));
  if (!result.ok) return fail(context, "the catalog accepted", result.code);
  return result.value;
}
