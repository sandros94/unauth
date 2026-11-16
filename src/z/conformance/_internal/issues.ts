import type { ValidationExpect } from "../types.ts";
import { isRecord } from "./data.ts";
import { type Attempt, type Context, fail } from "./outcome.ts";

/**
 * Checks what validation gave against what a case expects: the same issues by code and path, in
 * any order, or the code it threw. Each issue must also carry a message.
 */
export function expectIssues(
  context: Context,
  expected: ValidationExpect,
  result: Attempt<unknown>,
): void {
  if (typeof expected === "string") {
    const received = result.ok ? described(result.value) : result.code;
    if (received !== expected) fail(context, expected, received);
    return;
  }
  if (!result.ok) return fail(context, sorted(expected), result.code);
  const received = described(result.value);
  if (typeof received === "string") return fail(context, sorted(expected), received);
  const want = new Set(expected.map(keyOf));
  const got = new Set(received.map(keyOf));
  if (want.size !== got.size || [...want].some((key) => !got.has(key))) {
    fail(context, sorted(expected), sorted(received));
  }
}

interface Found {
  code: string;
  path: readonly (string | number)[];
}

function described(value: unknown): readonly Found[] | string {
  if (!Array.isArray(value)) return "no list of issues";
  const issues: Found[] = [];
  for (const item of value as unknown[]) {
    if (!isIssue(item)) return "an issue without a code, a path or a message";
    issues.push({ code: item.code, path: item.path });
  }
  return issues;
}

function isIssue(value: unknown): value is Found & { message: string } {
  return (
    isRecord(value) &&
    typeof value.code === "string" &&
    typeof value.message === "string" &&
    Array.isArray(value.path) &&
    value.path.every((part) => typeof part === "string" || typeof part === "number")
  );
}

function keyOf(issue: Found): string {
  return JSON.stringify([issue.code, issue.path]);
}

function sorted(issues: readonly Found[]): Found[] {
  const unique = new Map(issues.map((issue) => [keyOf(issue), issue]));
  return [...unique.entries()]
    .toSorted(([left], [right]) => (left > right ? 1 : -1))
    .map(([, { code, path }]) => ({ code, path }));
}
