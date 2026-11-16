import type { CompiledCatalog } from "../compiled.ts";
import { compareBytes, isToken } from "../grammar.ts";
import { chainOf } from "../keys.ts";
import { isLive } from "../time.ts";
import {
  type GrantsHead,
  own,
  ownRecord,
  readEntryMembers,
  readItems,
  shapeError,
} from "./form.ts";
import { placesOf, roleNames } from "./read.ts";

/**
 * The names of the roles the sets, each covering `place`, hold there at `time`: those with an
 * assignment item live at `time` at a key of the chain of `place`, sorted by bytes, each once. A
 * role is found as a read finds it: the names of `ps`, then of `sr`, then the presets of the
 * catalog, each looked up in `nt`. No role is resolved and no definition is read: of `ps` and `sr`
 * only the names, of `nt` only the entries under them, with their items, of `pl` only the places
 * those items point at, each checked to be a string and only compared with the keys of the chain.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for what it reads that is not in its form: `nt` not an
 * object, `ps` or `sr` of another type, a role name an entry is found under that is not a token,
 * such an entry or one of its items, `pl` of another type where an item names a place, and a place
 * read from `pl` that is not a string.
 */
export function heldRoles(
  catalog: CompiledCatalog,
  sets: readonly GrantsHead[],
  asked: { readonly place: string; readonly time: number },
): string[] {
  const chain = new Set(chainOf(asked.place));
  const held = new Set<string>();
  for (const head of sets) {
    for (const name of namesOf(catalog, head, chain, asked.time)) held.add(name);
  }
  return [...held].toSorted(compareBytes);
}

function namesOf(
  catalog: CompiledCatalog,
  head: GrantsHead,
  chain: ReadonlySet<string>,
  time: number,
): string[] {
  const { grants } = head;
  const nt = ownRecord(grants, "nt");
  if (!nt) throw shapeError(nt);
  const ps = ownRecord(grants, "ps");
  const sr = ownRecord(grants, "sr");
  const placeOf = placesOf(grants);
  const names: string[] = [];
  for (const name of roleNames(catalog, ps, sr)) {
    if (!Object.hasOwn(nt, name)) continue;
    if (!isToken(name)) throw shapeError(name);
    const items = readItems(readEntryMembers(own(nt, name), false), "a", placeOf);
    if (items.some((item) => isLive(item.end, time) && chain.has(item.place))) names.push(name);
  }
  return names;
}
