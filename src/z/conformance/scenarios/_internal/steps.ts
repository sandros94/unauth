import type { Statement, StatementKind } from "../../../types.ts";
import type { Question } from "../../engine.ts";
import type {
  AskStep,
  FromGrants,
  HandStep,
  IssueStep,
  ReadStep,
  ScenarioQuestion,
  WriteStep,
} from "../../types.ts";

/** Monday 2026-11-09 09:00 UTC, in seconds. */
export const MONDAY = 1794214800;
export const HOUR = 3600;
export const DAY = 86400;
/** Friday 2026-11-13 00:00 UTC, in seconds. */
export const FRIDAY_MIDNIGHT = 1794528000;

export function allow(
  subject: string,
  value: string,
  place?: string,
  expiresAt?: number,
): Statement {
  return statement("allow", subject, value, place, expiresAt);
}

export function assign(
  subject: string,
  value: string,
  place?: string,
  expiresAt?: number,
): Statement {
  return statement("assign", subject, value, place, expiresAt);
}

export function deny(
  subject: string,
  value: string,
  place?: string,
  expiresAt?: number,
): Statement {
  return statement("deny", subject, value, place, expiresAt);
}

export function exclude(
  subject: string,
  value: string,
  place?: string,
  expiresAt?: number,
): Statement {
  return statement("exclude", subject, value, place, expiresAt);
}

/** Asks the statements, and with `issuedAt` grants issued then too. */
export function ask(
  at: number,
  question: ScenarioQuestion,
  expect: AskStep["expect"],
  grants?: FromGrants,
): AskStep {
  return { step: "ask", at, question, expect, ...grants };
}

/** Hands the engine exactly `statements` for `subject`, and with `issuedAt` issues from them too. */
export function hand(
  at: number,
  subject: string,
  statements: readonly Statement[],
  question: Question,
  expect: HandStep["expect"],
  grants?: FromGrants,
): HandStep {
  return { step: "hand", at, subject, statements, question, expect, ...grants };
}

export function issue(
  at: number,
  as: string,
  subject: string,
  options?: Pick<IssueStep, "groups" | "bases" | "expect">,
): IssueStep {
  return { step: "issue", at, as, subject, ...options };
}

export function read(
  at: number,
  grants: ReadStep["grants"],
  question: Question,
  expect: ReadStep["expect"],
): ReadStep {
  return { step: "read", at, grants, question, expect };
}

export function write(rewrite: Omit<WriteStep, "step">): WriteStep {
  return { step: "write", ...rewrite };
}

function statement(
  kind: StatementKind,
  subject: string,
  value: string,
  place: string | undefined,
  expiresAt: number | undefined,
): Statement {
  const result: Statement = { kind, subject, value };
  if (place !== undefined) result.place = place;
  if (expiresAt !== undefined) result.expiresAt = expiresAt;
  return result;
}
