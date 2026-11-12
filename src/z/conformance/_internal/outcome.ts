import { isUnauthError } from "../../../error.ts";
import type { ConformanceFailure, PresetsWay } from "../types.ts";
import { isRecord, sameData } from "./data.ts";

export type Given = "everything" | "needed";

export const GIVEN: readonly Given[] = ["everything", "needed"];

export interface Context {
  id: string;
  step?: number;
  given?: Given;
  presets?: PresetsWay;
}

export type Attempt<T> = { ok: true; value: T } | { ok: false; code: string; error: unknown };

export function expectOutcome(context: Context, expected: string, result: Attempt<unknown>): void {
  const received = result.ok ? outcomeOf(result.value) : result.code;
  if (received !== expected) fail(context, expected, received);
}

export function outcomeOf(decision: unknown): string {
  if (!isRecord(decision) || typeof decision.allowed !== "boolean") return "no decision";
  if (decision.covered === false) return "not-covered";
  return decision.allowed ? "allowed" : "denied";
}

export function untouched<TInput, TResult>(
  context: Context,
  input: TInput,
  call: (copy: TInput) => TResult,
): Attempt<TResult> {
  const copy = structuredClone(input);
  const result = attempt(() => call(copy));
  if (!sameData(copy, input)) fail(context, "its input left as given", "its input changed");
  return result;
}

export function attempt<T>(call: () => T): Attempt<T> {
  try {
    return { ok: true, value: call() };
  } catch (error) {
    return { ok: false, code: describeThrown(error), error };
  }
}

export function describeThrown(error: unknown): string {
  if (isUnauthError(error)) return error.code;
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return `thrown ${String(error)}`;
}

export function fail(context: Context, expected: unknown, received: unknown): never {
  const failure: ConformanceFailure = { id: context.id, expected, received };
  if (context.step !== undefined) failure.step = context.step;
  if (context.given !== undefined) failure.given = context.given;
  if (context.presets !== undefined) failure.presets = context.presets;
  const where = [
    context.id,
    context.step === undefined ? "" : ` step ${context.step}`,
    context.given === undefined ? "" : ` given ${context.given}`,
    context.presets === undefined ? "" : ` presets as ${context.presets}`,
  ].join("");
  throw new Error(`${where}: expected ${show(expected)}, received ${show(received)}`, {
    cause: failure,
  });
}

export function failureOf(id: string, error: unknown): ConformanceFailure {
  if (error instanceof Error && isFailure(error.cause)) return error.cause;
  return { id, expected: "the case to run", received: describeThrown(error) };
}

export function isFailure(value: unknown): value is ConformanceFailure {
  return (
    isRecord(value) && typeof value.id === "string" && "expected" in value && "received" in value
  );
}

export function show(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value) ?? String(value);
  } catch {
    return String(value);
  }
}
