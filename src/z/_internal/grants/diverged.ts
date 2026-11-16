import { isRecord } from "../../../_internal/shared.ts";
import type { Diverged } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import { isPattern, isPermission, isToken, sortedUnique } from "../grammar.ts";
import { type GrantsHead, own, ownList, shapeError } from "./form.ts";
import { readDefinitions, readTable } from "./validate.ts";

/**
 * What of `sets` differs from `catalog`: the segments of the fingerprint that differ, the concrete
 * permissions the sets name that it does not declare, and the roles whose name no longer means the
 * same: a copy of a preset it no longer declares or declares with other entries, and a stored role
 * whose name it declares as a preset with other entries. A definition and a preset are compared as
 * sets of entries. `undefined` when every set was issued under the same segments as `catalog`, and
 * then nothing but the heads is read. Otherwise `pm`, `ps` and `sr` of every set are read whole,
 * and of a set without `pm` the names of `nt`, its concrete permissions being named there alone.
 * Neither the bases nor any entry is read, and a name in both `ps` and `sr` is not refused: no
 * read refuses it.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for a `pm`, `ps` or `sr` read that is not in its form,
 * and, in a set without `pm`, an `nt` that is not an object or a name of it that is not a pattern,
 * a role name or a permission.
 */
export function divergedOf(
  catalog: CompiledCatalog,
  sets: readonly GrantsHead[],
): Diverged | undefined {
  if (sets.every((set) => set.ct === catalog.fingerprint)) return undefined;
  const fingerprint = catalog.fingerprint.split(".");
  const segments = SEGMENTS.filter((_, index) =>
    sets.some((set) => set.ct.split(".")[index] !== fingerprint[index]),
  );
  if (segments.length === 0) return undefined;
  const permissions: string[] = [];
  const presets: string[] = [];
  for (const { grants } of sets) {
    const table = readTable(ownList(grants, "pm"));
    const permissionAt = (index: number) => table?.[index];
    const copies = readDefinitions(own(grants, "ps"), permissionAt);
    const stored = readDefinitions(own(grants, "sr"), permissionAt);
    for (const permission of table ?? namedPermissions(grants)) {
      if (!catalog.permissions.has(permission)) permissions.push(permission);
    }
    for (const [name, entries] of copies) {
      const declared = catalog.presetEntries.get(name);
      if (!declared || !sameSet(entries, declared)) presets.push(name);
    }
    for (const [name, entries] of stored) {
      const declared = catalog.presetEntries.get(name);
      if (declared && !sameSet(entries, declared)) presets.push(name);
    }
  }
  return { segments, permissions: sortedUnique(permissions), presets: sortedUnique(presets) };
}

const SEGMENTS: Diverged["segments"] = ["permissions", "presets"];

function namedPermissions(grants: Record<string, unknown>): string[] {
  const nt = own(grants, "nt");
  if (!isRecord(nt)) throw shapeError(nt);
  const names = Object.keys(nt);
  for (const name of names) if (!isPattern(name) && !isToken(name)) throw shapeError(name);
  return names.filter(isPermission);
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  const left = new Set(a);
  const right = new Set(b);
  return left.size === right.size && [...left].every((entry) => right.has(entry));
}
