import type { CatalogData } from "../../catalog.ts";
import type { Statement } from "../../types.ts";

const TOKEN = "[a-z][a-z0-9_-]{0,31}";
const PATTERN = new RegExp(`^(?:\\*|${TOKEN}:${TOKEN}|${TOKEN}:\\*|\\*:${TOKEN})$`);

/**
 * Whether a statement can relate to a question about `permission`, from the catalog alone, as
 * Section 7 of the model defines it. Wider than the model where it cannot tell: a value not in its
 * canonical form, an assignment of anything but a preset, and a preset by what it names without
 * its exclusions. `undefined` for a permission the catalog does not declare, whose question an
 * engine refuses.
 */
export function relatesTo(
  data: CatalogData,
  permission: string,
): ((statement: Statement) => boolean) | undefined {
  const declared = data.permissions;
  if (!declared.includes(permission)) return undefined;
  const implies = data.implies ?? {};
  const up = (from: string) =>
    reach(from, (p) => declared.filter((q) => (implies[q] ?? []).includes(p)));
  const wanted = up(permission);
  const blocking = reach(permission, (p) => implies[p] ?? []);
  return (statement) => {
    const { kind, value } = statement;
    if (kind === "assign") {
      const presets = data.presets ?? {};
      if (!Object.hasOwn(presets, value)) return true;
      return meets(wanted, presetNames(data, value, new Set()));
    }
    const expanded = expand(declared, value);
    if (expanded === undefined) return true;
    switch (kind) {
      case "allow": {
        return meets(wanted, expanded);
      }
      case "deny": {
        return meets(blocking, expanded);
      }
      case "exclude": {
        return expanded.some((named) => meets(wanted, up(named)));
      }
      default: {
        return true;
      }
    }
  };
}

function expand(declared: readonly string[], value: unknown): readonly string[] | undefined {
  if (typeof value !== "string" || !PATTERN.test(value)) return undefined;
  if (value === "*") return declared;
  if (value.endsWith(":*")) return declared.filter((p) => p.startsWith(value.slice(0, -1)));
  if (value.startsWith("*:")) return declared.filter((p) => p.endsWith(value.slice(1)));
  return declared.includes(value) ? [value] : [];
}

function presetNames(data: CatalogData, name: string, seen: Set<string>): string[] {
  seen.add(name);
  const presets: Readonly<Record<string, readonly string[]>> = data.presets ?? {};
  return (presets[name] ?? []).flatMap((entry) => {
    if (entry.startsWith("-")) return [];
    const permissions = expand(data.permissions, entry);
    if (permissions !== undefined) return [...permissions];
    return Object.hasOwn(presets, entry) && !seen.has(entry) ? presetNames(data, entry, seen) : [];
  });
}

function reach(from: string, next: (permission: string) => readonly string[]): Set<string> {
  const found = new Set([from]);
  for (const permission of found) for (const other of next(permission)) found.add(other);
  return found;
}

function meets(set: ReadonlySet<string>, values: Iterable<string>): boolean {
  for (const value of values) if (set.has(value)) return true;
  return false;
}
