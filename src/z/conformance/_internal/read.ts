import type { Catalog } from "../../catalog.ts";
import type { Engine, Question } from "../engine.ts";
import type { ExpectedDiverged } from "../types.ts";
import { clock, isRecord, sameData } from "./data.ts";
import { type Attempt, type Context, expectOutcome, fail, untouched } from "./outcome.ts";

/** Grants as a read is handed them: under which catalog, for which question, at which time. */
export interface Reading {
  catalog: Catalog;
  grants: unknown;
  question: Question;
  at: number;
}

/** What a read must give: its answer, and what it tells has diverged when the case says. */
export interface ReadExpect {
  expect: string;
  diverged?: ExpectedDiverged;
}

/**
 * Reads grants and checks the answer, then what is told has diverged: on the answer and from
 * `diverged` alone, both the same, and the one the case expects when it gives one. A read refused
 * for one of `refusals` must be refused by `diverged` alone with the same code.
 */
export function expectRead(
  engine: Engine,
  context: Context,
  reading: Reading,
  expected: ReadExpect,
  refusals: readonly string[],
): void {
  const now = clock(reading.at);
  const answer: Attempt<unknown> = untouched(
    context,
    { grants: reading.grants, question: reading.question },
    (input) => engine.could(reading.catalog, input.grants, input.question, { now }),
  );
  expectOutcome(context, expected.expect, answer);
  const told = untouched(context, reading.grants, (grants) =>
    engine.diverged(reading.catalog, grants, { now }),
  );
  const alone = told.ok ? (told.value ?? null) : told.code;
  const onAnswer = answer.ok ? divergedOn(answer.value) : undefined;
  if (expected.diverged !== undefined) {
    if (onAnswer !== undefined && !sameData(onAnswer, expected.diverged)) {
      fail(context, { diverged: expected.diverged }, { diverged: onAnswer });
    }
    if (!sameData(alone, expected.diverged)) {
      fail(context, { "diverged()": expected.diverged }, { "diverged()": alone });
    }
    return;
  }
  if (onAnswer !== undefined && !sameData(onAnswer, alone)) {
    fail(context, { "diverged()": onAnswer }, { "diverged()": alone });
  }
  if (!answer.ok && refusals.includes(answer.code) && alone !== answer.code) {
    fail(context, { "diverged()": answer.code }, { "diverged()": alone });
  }
}

/**
 * Validates grants whole, each set on its own, and checks the first refusal against `expected`,
 * `"valid"` when none may refuse.
 */
export function expectWhole(
  engine: Engine,
  context: Context,
  reading: Omit<Reading, "question">,
  expected: string,
): void {
  const now = clock(reading.at);
  let received = "valid";
  for (const set of Array.isArray(reading.grants)
    ? (reading.grants as unknown[])
    : [reading.grants]) {
    const result = untouched(context, set, (copy) =>
      engine.assertGrants(reading.catalog, copy, { now }),
    );
    if (!result.ok) {
      received = result.code;
      break;
    }
  }
  if (received !== expected) fail(context, { assertGrants: expected }, { assertGrants: received });
}

/**
 * The codes a read refuses grants with whatever the question, since every read meets what they
 * are about. A malformed part is met only by the reads that look there.
 */
export const GRANTS_REFUSALS: readonly string[] = [
  "ERR_AUTHZ_GRANTS_EARLY",
  "ERR_AUTHZ_GRANTS_FORMAT",
];

/** The codes a read refuses grants with for what they are, which validating them whole refuses too. */
export const WHOLE_REFUSALS: readonly string[] = [...GRANTS_REFUSALS, "ERR_AUTHZ_MALFORMED"];

function divergedOn(decision: unknown): unknown {
  return isRecord(decision) ? (decision.diverged ?? null) : null;
}
