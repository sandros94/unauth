import type { Catalog, CatalogData } from "../../catalog.ts";
import type { Statement, StoredRole } from "../../types.ts";
import type { Decision, Engine, Question, SubjectStatements } from "../engine.ts";
import type { AskStep, HandStep, IssueStep, ReadStep, WriteStep } from "../types.ts";
import { clock, identityOf } from "./data.ts";
import {
  type Attempt,
  type Context,
  GIVEN,
  type Given,
  expectOutcome,
  fail,
  untouched,
} from "./outcome.ts";
import { type Member, selectToAsk, selectToIssue } from "./select.ts";

export interface ScenarioState {
  data: CatalogData;
  catalog: Catalog;
  statements: Map<string, Statement>;
  roles: StoredRole[];
  grants: Map<string, Record<Given, unknown>>;
}

export function runAsk(
  engine: Engine,
  state: ScenarioState,
  step: AskStep,
  context: Context,
): void {
  const { subject, groups, ...question } = step.question;
  const member: Member = { subject, groups };
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const statements = selectToAsk(state.data, everything(state), {
      member,
      question,
      at: step.at,
      given,
    });
    const answer = askOf(engine, state, at, { subject, statements }, step, question);
    expectOutcome(at, step.expect, answer);
  }
  const { issuedAt } = step;
  if (issuedAt === undefined) return;
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const statements = selectToIssue(everything(state), {
      member,
      bases: step.bases,
      at: issuedAt,
      given,
    });
    const issued = issueOf(engine, state, at, { subject, statements }, { ...step, at: issuedAt });
    const answer = couldOf(engine, state, at, issued, step, question);
    expectOutcome(at, step.fromGrants ?? step.expect, answer);
  }
}

export function runHand(
  engine: Engine,
  state: ScenarioState,
  step: HandStep,
  context: Context,
): void {
  const read = { subject: step.subject, statements: step.statements };
  expectOutcome(context, step.expect, askOf(engine, state, context, read, step, step.question));
  if (step.issuedAt === undefined) return;
  const issued = issueOf(engine, state, context, read, { ...step, at: step.issuedAt });
  const answer = couldOf(engine, state, context, issued, step, step.question);
  expectOutcome(context, step.fromGrants ?? step.expect, answer);
}

export function runIssue(
  engine: Engine,
  state: ScenarioState,
  step: IssueStep,
  context: Context,
): void {
  const kept: Partial<Record<Given, unknown>> = {};
  for (const given of GIVEN) {
    const at: Context = { ...context, given };
    const statements = selectToIssue(everything(state), {
      member: step,
      bases: step.bases,
      at: step.at,
      given,
    });
    const issued = issueOf(engine, state, at, { subject: step.subject, statements }, step);
    if (step.expect !== undefined) {
      const received = issued.ok ? "issued" : issued.code;
      if (received !== step.expect) fail(at, step.expect, received);
      continue;
    }
    if (!issued.ok) fail(at, "issued", issued.code);
    kept[given] = structuredClone(issued.value);
  }
  if (step.expect === undefined) {
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
    const kept = (name: string): unknown => {
      const issued = state.grants.get(name);
      if (issued === undefined) return fail(at, `grants issued as "${name}"`, "none");
      return issued[given];
    };
    const grants = typeof step.grants === "string" ? kept(step.grants) : step.grants.map(kept);
    const result = untouched(at, { grants, question: step.question }, (input) =>
      engine.could(state.catalog, input.grants, input.question, { now }),
    );
    expectOutcome(at, step.expect, result);
  }
}

export function runWrite(state: ScenarioState, step: WriteStep): void {
  for (const statement of step.save ?? []) storeStatement(state, statement);
  for (const identity of step.remove ?? []) state.statements.delete(identityOf(identity));
  if (step.roles !== undefined) state.roles = structuredClone([...step.roles]);
}

export function storeStatement(state: ScenarioState, statement: Statement): void {
  state.statements.set(identityOf(statement), structuredClone(statement));
}

function askOf(
  engine: Engine,
  state: ScenarioState,
  context: Context,
  read: Omit<SubjectStatements, "roles">,
  step: { at: number },
  question: Question,
): Attempt<Decision> {
  const input = { read: { ...read, roles: state.roles }, question };
  const now = clock(step.at);
  return untouched(context, input, (copy) =>
    engine.ask(state.catalog, copy.read, copy.question, { now }),
  );
}

function issueOf(
  engine: Engine,
  state: ScenarioState,
  context: Context,
  read: Omit<SubjectStatements, "roles">,
  options: { bases?: readonly string[]; at: number },
): Attempt<unknown> {
  const input = { read: { ...read, roles: state.roles }, bases: options.bases };
  const now = clock(options.at);
  return untouched(context, input, (copy) =>
    engine.issueGrants(state.catalog, copy.read, {
      ...(copy.bases !== undefined && { bases: copy.bases }),
      now,
    }),
  );
}

function couldOf(
  engine: Engine,
  state: ScenarioState,
  context: Context,
  issued: Attempt<unknown>,
  step: { at: number },
  question: Question,
): Attempt<Decision> {
  if (!issued.ok) return issued;
  const now = clock(step.at);
  return untouched(context, { grants: issued.value, question }, (input) =>
    engine.could(state.catalog, input.grants, input.question, { now }),
  );
}

function everything(state: ScenarioState): Statement[] {
  return [...state.statements.values()];
}
