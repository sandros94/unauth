import type { Statement, StoredRole } from "../../types.ts";

export function identityOf(
  statement: Pick<Statement, "kind" | "subject" | "value" | "place">,
): string {
  return JSON.stringify([statement.kind, statement.subject, statement.value, placeOf(statement)]);
}

export function roleKey(role: StoredRole): string {
  return JSON.stringify([role.name, role.home ?? "/"]);
}

export function placeOf(statement: Pick<Statement, "place">): string {
  return statement.place ?? "/";
}

export function chainOf(key: string): string[] {
  const chain = [key];
  let current = key;
  while (current !== "/") {
    const cut = current.lastIndexOf("/");
    current = cut <= 0 ? "/" : current.slice(0, cut);
    chain.push(current);
  }
  return chain;
}

export function covers(outer: string, inner: string): boolean {
  return outer === "/" || inner === outer || inner.startsWith(`${outer}/`);
}

export function clock(seconds: number): () => number {
  return () => seconds * 1000;
}

export function uniqueSorted(values: readonly string[]): string[] {
  return [...new Set(values)].toSorted();
}

export function sameData(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (Array.isArray(left) || Array.isArray(right)) {
    return (
      Array.isArray(left) &&
      Array.isArray(right) &&
      left.length === right.length &&
      left.every((item, index) => sameData(item, right[index]))
    );
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const keys = Object.keys(left);
  return (
    keys.length === Object.keys(right).length &&
    keys.every((key) => Object.hasOwn(right, key) && sameData(left[key], right[key]))
  );
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
