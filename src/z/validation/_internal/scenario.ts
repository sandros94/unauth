import type { Catalog } from "../../catalog.ts";
import type { Decision, Grants, GrantsQuestion, Statement, StoredRole } from "../../types.ts";
import type { AskStep, Engine, IssueStep, ReadStep, WriteStep } from "../types.ts";
import { chainOf, clock, covers, identityOf, placeOf, roleKey } from "./data.ts";
import {
  type Attempt,
  type Context,
  GIVEN,
  type Given,
  expectOutcome,
  fail,
  untouched,
} from "./outcome.ts";

export interface ScenarioState {
  catalog: Catalog;
  statements: Map<string, Statement>;
  roles: Map<string, StoredRole>;
  grants: Map<string, Record<Given, Grants>>;
}

export function runAsk(
  engine: Engine,
  state: ScenarioState,
  step: AskStep,
  context: Context,
): void {
  const { question } = step;
  const identifiers = new Set([question.subject, ...(question.groups ?? [])]);
  const onChain = new Set(chainOf(question.place ?? "/"));
  const now = clock(step.at);
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const statements =
      given === "everything"
        ? everything(state)
        : everything(state).filter(
            (statement) => identifiers.has(statement.subject) && onChain.has(placeOf(statement)),
          );
    const result = untouched(at, { question, statements, roles: allRoles(state) }, (input) =>
      engine.decide(state.catalog, input.question, {
        statements: input.statements,
        roles: input.roles,
        now,
      }),
    );
    expectOutcome(at, step.expect, result);
  }
  if (step.issuedAt === undefined) return;
  const grantsQuestion = toGrantsQuestion(step);
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const issued = issueFor(engine, state, at, {
      subject: question.subject,
      groups: question.groups,
      bases: step.bases,
      at: step.issuedAt,
    });
    const result: Attempt<Decision> = issued.ok
      ? untouched(at, { grants: issued.value, question: grantsQuestion }, (input) =>
          engine.readGrants(state.catalog, input.grants, input.question, { now }),
        )
      : issued;
    expectOutcome(at, step.fromGrants ?? step.expect, result);
  }
}

export function runIssue(
  engine: Engine,
  state: ScenarioState,
  step: IssueStep,
  context: Context,
): void {
  const kept: Partial<Record<Given, Grants>> = {};
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const issued = issueFor(engine, state, at, step);
    if (step.expect !== undefined) {
      const received = issued.ok ? "issued" : issued.code;
      if (received !== step.expect) fail(at, step.expect, received);
      continue;
    }
    if (!issued.ok) fail(at, "issued", issued.code);
    kept[given] = structuredClone(issued.value);
  }
  if (kept.everything !== undefined && kept.needed !== undefined) {
    state.grants.set(step.as, { everything: kept.everything, needed: kept.needed });
  }
}

export function runRead(
  engine: Engine,
  state: ScenarioState,
  step: ReadStep,
  context: Context,
): void {
  const now = clock(step.at);
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const kept = (name: string): Grants => {
      const issued = state.grants.get(name);
      if (issued === undefined) return fail(at, `grants issued as "${name}"`, "none");
      return issued[given];
    };
    const grants = typeof step.grants === "string" ? kept(step.grants) : step.grants.map(kept);
    const result = untouched(at, { grants, question: step.question }, (input) =>
      engine.readGrants(state.catalog, input.grants, input.question, { now }),
    );
    expectOutcome(at, step.expect, result);
  }
}

export function runWrite(state: ScenarioState, step: WriteStep): void {
  for (const statement of step.save ?? []) storeStatement(state, statement);
  for (const identity of step.remove ?? []) state.statements.delete(identityOf(identity));
  if (step.roles !== undefined) {
    state.roles.clear();
    for (const role of step.roles) state.roles.set(roleKey(role), structuredClone(role));
  }
}

function issueFor(
  engine: Engine,
  state: ScenarioState,
  context: Context,
  request: { subject: string; groups?: readonly string[]; bases?: readonly string[]; at: number },
): Attempt<Grants> {
  const identifiers = new Set([request.subject, ...(request.groups ?? [])]);
  const bases = request.bases ?? [];
  const about = everything(state).filter((statement) => identifiers.has(statement.subject));
  const statements =
    context.given === "everything"
      ? everything(state)
      : bases.length === 0
        ? about
        : about.filter((statement) => {
            const place = placeOf(statement);
            return bases.some((base) => chainOf(base).includes(place) || covers(base, place));
          });
  const input = {
    subject: request.subject,
    groups: request.groups,
    bases: request.bases,
    statements,
    roles: allRoles(state),
  };
  const now = clock(request.at);
  return untouched(context, input, (copy) =>
    engine.issueGrants(state.catalog, copy.subject, {
      groups: copy.groups,
      bases: copy.bases,
      statements: copy.statements,
      roles: copy.roles,
      now,
    }),
  );
}

function toGrantsQuestion(step: AskStep): GrantsQuestion {
  const { permission, place } = step.question;
  return { permission, place };
}

export function everything(state: ScenarioState): Statement[] {
  return [...state.statements.values()];
}

export function allRoles(state: ScenarioState): StoredRole[] {
  return [...state.roles.values()];
}

export function storeStatement(state: ScenarioState, statement: Statement): void {
  state.statements.set(identityOf(statement), structuredClone(statement));
}
