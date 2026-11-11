const TOKEN = /^[a-z][a-z0-9_-]{0,31}$/;

/** A role entry split into its parts: whether it excludes, and what it names. */
export interface EntryParts {
  /** Written with the `-` prefix. */
  exclude: boolean;
  /** `pattern` for `*` or anything holding `:`, `role` for anything else. */
  kind: "pattern" | "role";
  /** The entry without its prefix: a pattern, or a role name. */
  name: string;
}

/** Whether `value` is a token: a lowercase ASCII letter, then up to 31 lowercase letters, digits, `-` or `_`. */
export function isToken(value: unknown): value is string {
  return typeof value === "string" && TOKEN.test(value);
}

/** Whether `value` is a concrete permission: two tokens joined by `:`. */
export function isPermission(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const colon = value.indexOf(":");
  return colon > 0 && isToken(value.slice(0, colon)) && isToken(value.slice(colon + 1));
}

/** Whether `value` is a pattern: a permission, `resource:*`, `*:action` or `*`. Never `*:*`. */
export function isPattern(value: unknown): value is string {
  if (value === "*") return true;
  if (typeof value !== "string") return false;
  const colon = value.indexOf(":");
  if (colon < 0) return false;
  const resource = value.slice(0, colon);
  const action = value.slice(colon + 1);
  if (resource === "*") return isToken(action);
  return isToken(resource) && (action === "*" || isToken(action));
}

/**
 * Reads a role entry: the `-` prefix first, then `*` or a value holding `:` is a pattern, anything
 * else a role name. `undefined` when the entry, or what follows `-`, does not match its grammar.
 */
export function readEntry(entry: unknown): EntryParts | undefined {
  if (typeof entry !== "string") return undefined;
  const exclude = entry.startsWith("-");
  const name = exclude ? entry.slice(1) : entry;
  if (name === "*" || name.includes(":")) {
    return isPattern(name) ? { exclude, kind: "pattern", name } : undefined;
  }
  return isToken(name) ? { exclude, kind: "role", name } : undefined;
}

/**
 * Orders two strings by the bytes of their UTF-8 encoding, which is the order of their code
 * points: never by a language's collation.
 */
export function compareBytes(a: string, b: string): number {
  const length = Math.min(a.length, b.length);
  for (let index = 0; index < length; index++) {
    const x = a.codePointAt(index) ?? 0;
    const y = b.codePointAt(index) ?? 0;
    if (x !== y) return x < y ? -1 : 1;
    if (x > 0xffff) index++;
  }
  return a.length === b.length ? 0 : a.length < b.length ? -1 : 1;
}

/** The values once each, ordered by {@link compareBytes}. */
export function sortedUnique(values: Iterable<string>): string[] {
  return [...new Set(values)].toSorted(compareBytes);
}
