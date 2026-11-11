import type { Statement } from "../../types.ts";
import type { ChangeReason, ChangeStep, Engine, GenesisStep, ScenarioRefusal } from "../types.ts";
import { clock, identityOf, placeOf, roleKey, sameData, uniqueSorted } from "./data.ts";
import { type Attempt, type Context, GIVEN, fail, reasonsOf, untouched } from "./outcome.ts";
import { type ScenarioState, allRoles, everything, storeStatement } from "./scenario.ts";

export function runChange(
  engine: Engine,
  state: ScenarioState,
  step: ChangeStep,
  context: Context,
): void {
  const identifiers = new Set([step.author, ...(step.groups ?? [])]);
  const managers = rootManagers(state);
  const now = clock(step.at);
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const statements =
      given === "everything"
        ? everything(state)
        : everything(state).filter((statement) => identifiers.has(statement.subject));
    const input = {
      change: step.change,
      author: step.author,
      groups: step.groups,
      statements,
      roles: allRoles(state),
      managers,
    };
    const result = untouched(at, input, (copy) =>
      engine.checkChange(state.catalog, copy.change, {
        author: copy.author,
        groups: copy.groups,
        statements: copy.statements,
        roles: copy.roles,
        managers: copy.managers,
        now,
      }),
    );
    expectChange(at, step, result);
  }
  if (step.expect !== "accepted") return;
  const { change } = step;
  if (change.action === "define")
    state.roles.set(roleKey(change.role), structuredClone(change.role));
  else if (change.action === "place") storeStatement(state, change.statement);
  else state.statements.delete(identityOf(change.statement));
}

export function runGenesis(
  engine: Engine,
  state: ScenarioState,
  step: GenesisStep,
  context: Context,
): void {
  const input = { statement: step.statement, managers: rootManagers(state) };
  const now = clock(step.at);
  const result = untouched(context, input, (copy) =>
    engine.checkGenesis(state.catalog, copy.statement, { managers: copy.managers, now }),
  );
  expectChange(context, step, result);
  if (step.expect === "accepted") storeStatement(state, step.statement);
}

function expectChange(
  context: Context,
  step: { expect: "accepted" | ScenarioRefusal; reasons?: readonly ChangeReason[] },
  result: Attempt<unknown>,
): void {
  const received = result.ok ? "accepted" : result.code;
  if (received !== step.expect) fail(context, step.expect, received);
  if (result.ok || step.reasons === undefined) return;
  const expected = uniqueSorted(step.reasons);
  const reasons = reasonsOf(result.error);
  if (reasons === undefined || !sameData(uniqueSorted(reasons), expected)) {
    fail(context, { code: step.expect, reasons: expected }, { code: result.code, reasons });
  }
}

function rootManagers(state: ScenarioState): Statement[] {
  return everything(state).filter(
    (statement) =>
      statement.kind === "allow" &&
      statement.value === "*" &&
      placeOf(statement) === "/" &&
      statement.expiresAt === undefined,
  );
}
