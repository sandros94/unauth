import { clock, isRecord, sameData } from "./_internal/data.ts";
import { defineFor, loose } from "./_internal/define.ts";
import { expectIssues } from "./_internal/issues.ts";
import {
  type Context,
  attempt,
  expectOutcome,
  fail,
  failureOf,
  untouched,
} from "./_internal/outcome.ts";
import {
  type ScenarioState,
  runAsk,
  runHand,
  runIssue,
  runRead,
  runWrite,
  storeStatement,
} from "./_internal/scenario.ts";
import type { Engine } from "./engine.ts";
import type {
  Cases,
  CatalogCase,
  ConformanceReport,
  GrantsCase,
  PlaceCase,
  RoleCase,
  Scenario,
  StatementCase,
} from "./types.ts";

/**
 * Runs a scenario against an engine, step by step, over the statements and stored roles it keeps.
 * The runner plays the application: for each call it hands the engine the statements about the
 * subject and its groups, once all of them and once only those the call needs, and both answers
 * must be the one the step expects. A `hand` step hands exactly the statements it lists.
 *
 * @throws an `Error` whose `cause` is a `ConformanceFailure` at the first wrong answer.
 */
export function runScenario(engine: Engine, scenario: Scenario): void {
  const state: ScenarioState = {
    data: scenario.catalog,
    catalog: defineFor(engine, scenario.catalog, { id: scenario.id }),
    statements: new Map(),
    roles: structuredClone([...(scenario.roles ?? [])]),
    grants: new Map(),
  };
  for (const statement of scenario.statements ?? []) storeStatement(state, statement);
  for (const [index, step] of scenario.steps.entries()) {
    const context: Context = { id: scenario.id, step: index };
    switch (step.step) {
      case "ask": {
        runAsk(engine, state, step, context);
        break;
      }
      case "hand": {
        runHand(engine, state, step, context);
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
      case "write": {
        runWrite(state, step);
        break;
      }
    }
  }
}

/**
 * Runs every case and reports which passed and which answered otherwise. Never throws for a wrong
 * answer.
 */
export function runConformance(engine: Engine, cases: Cases): ConformanceReport {
  const report: ConformanceReport = { passed: [], failed: [] };
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
  for (const item of cases.statementCases) run(item.id, () => runStatementCase(engine, item));
  for (const item of cases.roleCases) run(item.id, () => runRoleCase(engine, item));
  return report;
}

/**
 * Checks that an engine accepts or refuses a catalog, and computes the fingerprint given.
 *
 * @throws an `Error` whose `cause` is a `ConformanceFailure` on a wrong answer.
 */
export function runCatalogCase(engine: Engine, catalogCase: CatalogCase): void {
  const context: Context = { id: catalogCase.id };
  const result = untouched(context, catalogCase.catalog, (data) =>
    loose(engine).defineCatalog(data),
  );
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
 * @throws an `Error` whose `cause` is a `ConformanceFailure` on a wrong answer.
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
 * @throws an `Error` whose `cause` is a `ConformanceFailure` on a wrong answer.
 */
export function runGrantsCase(engine: Engine, grantsCase: GrantsCase): void {
  const context: Context = { id: grantsCase.id };
  const catalog = defineFor(engine, grantsCase.catalog, context);
  const grants: unknown = structuredClone(grantsCase.grants);
  if (isRecord(grants) && grants.ct === "$ct") grants.ct = catalog.fingerprint;
  const now = clock(grantsCase.at);
  const result = untouched(context, { grants, question: grantsCase.question }, (input) =>
    engine.could(catalog, input.grants, input.question, { now }),
  );
  expectOutcome(context, grantsCase.expect, result);
}

/**
 * Validates a statement at the time of the case, with its stored roles, and checks the issues
 * found are those the case expects, in any order, or the code thrown.
 *
 * @throws an `Error` whose `cause` is a `ConformanceFailure` on a wrong answer.
 */
export function runStatementCase(engine: Engine, statementCase: StatementCase): void {
  const context: Context = { id: statementCase.id };
  const catalog = defineFor(engine, statementCase.catalog, context);
  const input = { statement: statementCase.statement, roles: statementCase.roles };
  const now = clock(statementCase.at);
  const result = untouched(context, input, (copy) =>
    engine.validateStatement(catalog, copy.statement, { ...withRoles(copy.roles), now }),
  );
  expectIssues(context, statementCase.expect, result);
}

/**
 * Validates a stored role, with the other stored roles of the case, and checks the issues found
 * are those the case expects, in any order, or the code thrown.
 *
 * @throws an `Error` whose `cause` is a `ConformanceFailure` on a wrong answer.
 */
export function runRoleCase(engine: Engine, roleCase: RoleCase): void {
  const context: Context = { id: roleCase.id };
  const catalog = defineFor(engine, roleCase.catalog, context);
  const input = { role: roleCase.role, roles: roleCase.roles };
  const result = untouched(context, input, (copy) =>
    engine.validateRole(catalog, copy.role, withRoles(copy.roles)),
  );
  expectIssues(context, roleCase.expect, result);
}

function withRoles<T>(roles: T | undefined): { roles: T } | undefined {
  return roles === undefined ? undefined : { roles };
}
