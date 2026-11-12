import type { Catalog, CatalogData } from "../../catalog.ts";
import type { Statement, StoredRole } from "../../types.ts";
import type { Decision, Engine, Question, SubjectStatements } from "../engine.ts";
import type {
  AskStep,
  DeployStep,
  FromGrants,
  HandStep,
  IssueStep,
  PresetsWay,
  ReadStep,
  WriteStep,
} from "../types.ts";
import { clock, identityOf } from "./data.ts";
import { defineFor } from "./define.ts";
import {
  type Attempt,
  type Context,
  GIVEN,
  type Given,
  expectOutcome,
  fail,
  untouched,
} from "./outcome.ts";
import { GRANTS_REFUSALS, expectRead } from "./read.ts";
import { type Member, selectToAsk, selectToIssue } from "./select.ts";

export interface ScenarioState {
  data: CatalogData;
  catalog: Catalog;
  statements: Map<string, Statement>;
  roles: StoredRole[];
  grants: Map<string, Issued>;
}

/** Grants a step issued, by the way presets travel in them, then by what the runner handed over. */
export type Issued = Partial<Record<PresetsWay, Record<Given, unknown>>>;

export const WAYS: readonly PresetsWay[] = ["copies", "names"];

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
    const statements = selectToIssue(everything(state), {
      member,
      bases: step.bases,
      at: issuedAt,
      given,
    });
    fromGrants(engine, state, { ...context, given }, { subject, statements }, step, question);
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
  fromGrants(engine, state, context, read, step, step.question);
}

export function runIssue(
  engine: Engine,
  state: ScenarioState,
  step: IssueStep,
  context: Context,
): void {
  const kept: Issued = {};
  for (const presets of step.presets === undefined ? WAYS : [step.presets]) {
    const set: Partial<Record<Given, unknown>> = {};
    for (const given of GIVEN) {
      const at: Context = { ...context, given, presets };
      const statements = selectToIssue(everything(state), {
        member: step,
        bases: step.bases,
        at: step.at,
        given,
      });
      const read = { subject: step.subject, statements };
      const issued = issueOf(engine, state, at, read, { ...step, presets });
      if (step.expect !== undefined) {
        const received = issued.ok ? "issued" : issued.code;
        if (received !== step.expect) fail(at, step.expect, received);
        continue;
      }
      if (!issued.ok) fail(at, "issued", issued.code);
      set[given] = structuredClone(issued.value);
    }
    kept[presets] = { everything: set.everything, needed: set.needed };
  }
  if (step.expect === undefined) state.grants.set(step.as, kept);
}

export function runRead(
  engine: Engine,
  state: ScenarioState,
  step: ReadStep,
  context: Context,
): void {
  const names = typeof step.grants === "string" ? [step.grants] : step.grants;
  const sets = names.map((name) => {
    const issued = state.grants.get(name);
    if (issued === undefined) return fail(context, `grants issued as "${name}"`, "none");
    return issued;
  });
  for (const presets of WAYS.filter((way) => sets.some((set) => set[way] !== undefined))) {
    for (const given of GIVEN) {
      const at: Context = { ...context, given, presets };
      const read = sets.map((set) => (set[presets] ?? Object.values(set)[0])?.[given]);
      const grants = typeof step.grants === "string" ? read[0] : read;
      expectRead(engine, at, { ...step, catalog: state.catalog, grants }, step, GRANTS_REFUSALS);
    }
  }
}

export function runDeploy(
  engine: Engine,
  state: ScenarioState,
  step: DeployStep,
  context: Context,
): void {
  state.data = step.catalog;
  state.catalog = defineFor(engine, step.catalog, context);
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

function fromGrants(
  engine: Engine,
  state: ScenarioState,
  context: Context,
  read: Omit<SubjectStatements, "roles">,
  step: FromGrants & { at: number; expect: string },
  question: Question,
): void {
  if (step.issuedAt === undefined) return;
  const expect = step.fromGrants ?? step.expect;
  for (const presets of WAYS) {
    const at: Context = { ...context, presets };
    const issued = issueOf(engine, state, at, read, { ...step, at: step.issuedAt, presets });
    if (!issued.ok) {
      expectOutcome(at, expect, issued);
      continue;
    }
    const reading = { catalog: state.catalog, grants: issued.value, question, at: step.at };
    expectRead(engine, at, reading, { expect }, GRANTS_REFUSALS);
  }
}

function issueOf(
  engine: Engine,
  state: ScenarioState,
  context: Context,
  read: Omit<SubjectStatements, "roles">,
  options: { bases?: readonly string[]; at: number; presets?: PresetsWay },
): Attempt<unknown> {
  const input = { read: { ...read, roles: state.roles }, bases: options.bases };
  const now = clock(options.at);
  const omit = options.presets === "names" ? { omit: ["presets"] as const } : undefined;
  return untouched(context, input, (copy) =>
    engine.issueGrants(state.catalog, copy.read, {
      ...(copy.bases !== undefined && { bases: copy.bases }),
      ...omit,
      now,
    }),
  );
}

function everything(state: ScenarioState): Statement[] {
  return [...state.statements.values()];
}
