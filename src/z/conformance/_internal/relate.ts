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
  const implies: Readonly<Record<string, readonly string[] | undefined>> = data.implies ?? {};
  const implying = new Map<string, string[]>();
  for (const [from, implied] of Object.entries(implies)) {
    for (const to of implied ?? []) implying.set(to, [...(implying.get(to) ?? []), from]);
  }
  const up = (from: string) => reach(from, (p) => implying.get(p) ?? []);
  const wanted = up(permission);
  const blocking = reach(permission, (p) => implies[p] ?? []);
  return (statement) => {
    const { kind, value } = statement;
    if (kind === "assign") {
      const presets = data.presets ?? {};
      if (!Object.hasOwn(presets, value)) return true;
      return meets(wanted, presetNames(data, value));
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

function presetNames(data: CatalogData, name: string): string[] {
  const presets: Readonly<Record<string, readonly string[]>> = data.presets ?? {};
  const seen = new Set([name]);
  const names: string[] = [];
  for (const role of seen) {
    for (const entry of presets[role] ?? []) {
      if (entry.startsWith("-")) continue;
      const permissions = expand(data.permissions, entry);
      if (permissions !== undefined) names.push(...permissions);
      else if (Object.hasOwn(presets, entry)) seen.add(entry);
    }
  }
  return names;
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
