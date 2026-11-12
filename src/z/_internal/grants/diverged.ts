import type { Diverged } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import { sortedUnique } from "../grammar.ts";
import type { GrantsSetRead } from "./validate.ts";

/**
 * What of `sets` differs from `catalog`: the segments of the fingerprint that differ, the concrete
 * permissions the sets name that it does not declare, and the roles whose name no longer means the
 * same: a copy of a preset it no longer declares or declares with other entries, and a stored role
 * whose name it declares as a preset with other entries. A definition and a preset are compared as
 * sets of entries.
 * `undefined` when every set was issued under the same segments as `catalog`.
 */
export function divergedOf(
  catalog: CompiledCatalog,
  sets: readonly GrantsSetRead[],
): Diverged | undefined {
  const own = catalog.fingerprint.split(".");
  const segments = new Set<Diverged["segments"][number]>();
  const permissions: string[] = [];
  const presets: string[] = [];
  for (const set of sets) {
    const [declares, copied] = set.ct.split(".");
    if (declares !== own[0]) segments.add("permissions");
    if (copied !== own[1]) segments.add("presets");
    for (const permission of set.permissions) {
      if (!catalog.permissions.has(permission)) permissions.push(permission);
    }
    for (const [name, entries] of set.copies) {
      const declared = catalog.presetEntries.get(name);
      if (!declared || !sameSet(entries, declared)) presets.push(name);
    }
    for (const [name, entries] of set.stored) {
      const declared = catalog.presetEntries.get(name);
      if (declared && !sameSet(entries, declared)) presets.push(name);
    }
  }
  if (segments.size === 0) return undefined;
  return {
    segments: SEGMENTS.filter((segment) => segments.has(segment)),
    permissions: sortedUnique(permissions),
    presets: sortedUnique(presets),
  };
}

const SEGMENTS: Diverged["segments"] = ["permissions", "presets"];

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const left = new Set(a);
  const right = new Set(b);
  return left.size === right.size && [...left].every((entry) => right.has(entry));
}
