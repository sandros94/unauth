import type { Decision, Statement } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import type { GrantsItemRead, GrantsSetRead } from "./validate.ts";
import { covers } from "../keys.ts";
import { blocking, down, expand, removed, spellings, wanted } from "../permissions.ts";
import { isLive } from "../time.ts";

/** The item of grants that decided a permission, in the shape of a statement without its subject. */
type GrantsBy = Omit<Statement, "subject">;

/** Whether some base of the set covers `place`, a canonical key. */
export function coversPlace(set: GrantsSetRead, place: string): boolean {
  return set.bases.some((base) => covers(base, place));
}

/**
 * Answers one declared, concrete permission from one set of grants at a place it covers and at one
 * time, as the model's `read`: a live deny of a value that can carry what blocks the permission, at
 * a place covering the target, denies; else a live given value at a place covering the target
 * allows when one of the permissions it gives satisfies the question and no live exclusion between
 * its place and the target, of no bundle or of its own, takes that permission out. Only the values
 * that can bear on the permission are looked up.
 */
export function readSet(
  catalog: CompiledCatalog,
  set: GrantsSetRead,
  asked: { readonly permission: string; readonly place: string; readonly time: number },
): Omit<Decision, "covered"> {
  const { permission } = asked;
  const applies = (item: GrantsItemRead) =>
    isLive(item.end, asked.time) && covers(item.place, asked.place);
  for (const value of spelled(blocking(catalog, permission))) {
    const item = set.entries.get(value)?.d.find(applies);
    if (item) return { allowed: false, by: byOf("deny", value, item) };
  }
  const satisfying = wanted(catalog, permission);
  const exclusions = [...spelled(down(catalog, permission))].flatMap((value) =>
    (set.entries.get(value)?.x ?? [])
      .filter(applies)
      .map((item) => ({ item, taken: removed(catalog, value) })),
  );
  for (const [value, kind, gives] of givenValues(catalog, set, satisfying)) {
    for (const item of set.entries.get(value)?.a ?? []) {
      if (!applies(item)) continue;
      const left = [...gives].some(
        (given) =>
          satisfying.has(given) &&
          !exclusions.some(
            (exclusion) =>
              covers(item.place, exclusion.item.place) &&
              exclusion.taken.has(given) &&
              (exclusion.item.bundle === undefined || exclusion.item.bundle === item.bundle),
          ),
      );
      if (left) return { allowed: true, by: byOf(kind, value, item) };
    }
  }
  return { allowed: false };
}

/**
 * The values of grants that can give something in `satisfying`, with what each gives: the
 * spellings of those permissions, the presets that resolve to one, the rows that hold one.
 */
function givenValues(
  catalog: CompiledCatalog,
  set: GrantsSetRead,
  satisfying: ReadonlySet<string>,
): [value: string, kind: "allow" | "assign", gives: ReadonlySet<string>][] {
  const meets = (gives: ReadonlySet<string>) => [...satisfying].some((p) => gives.has(p));
  const out: [string, "allow" | "assign", ReadonlySet<string>][] = [];
  for (const value of spelled(satisfying)) out.push([value, "allow", expand(catalog, value)]);
  for (const [name, role] of catalog.presets) {
    if (meets(role.gives)) out.push([name, "assign", role.gives]);
  }
  set.rows.forEach((row, index) => {
    if (meets(row)) out.push([`#${index}`, "assign", row]);
  });
  return out;
}

function spelled(permissions: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const permission of permissions) for (const value of spellings(permission)) out.add(value);
  return out;
}

function byOf(kind: GrantsBy["kind"], value: string, item: GrantsItemRead): GrantsBy {
  return item.end === undefined
    ? { kind, value, place: item.place }
    : { kind, value, place: item.place, expiresAt: item.end };
}
