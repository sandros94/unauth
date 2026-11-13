import type { Decision, Statement, StoredRole } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import { isPermission, isToken } from "../grammar.ts";
import { chainOf, covers } from "../keys.ts";
import { blocking, down, expand, removed, spellings, wanted } from "../permissions.ts";
import { readerOver } from "../roles.ts";
import { isLive } from "../time.ts";
import {
  type GrantsHead,
  type GrantsItemRead,
  type PlaceOf,
  own,
  ownList,
  ownRecord,
  readDefinition,
  readEntryMembers,
  readItems,
  shapeError,
} from "./form.ts";

/** The item of grants that decided a permission, in the shape of a statement without its subject. */
type GrantsBy = Omit<Statement, "subject">;

/** Who asks of one set of grants: one declared, concrete permission, at a place that fits, at one time. */
export interface AskedOfGrants {
  readonly permission: string;
  readonly place: string;
  readonly time: number;
}

/**
 * Answers one permission from one set of grants at a place one of its bases covers, as the model's
 * `read`, reading only what the question looks up: under the spellings of what blocks the
 * permission, the denies; of what takes out what satisfies it, the exclusions; of what satisfies
 * it, what is given; then the roles named in `ps`, then in `sr`, then the presets of the catalog,
 * in that order, each resolved only once one of its items applies. A permission is looked up by its
 * position where the set holds `pm`. Every item of an entry looked up is checked, ended or not,
 * whatever the answer. Of `pl`, only the places those items point at are read, and only compared
 * with the keys of the chain of the target: a place in another spelling covers nothing. A live deny at a covering place
 * denies; else a live given value at a covering place allows when one of the permissions it gives
 * satisfies the question and no live exclusion between its place and the target, of no bundle or
 * of its own, takes that permission out. A role name is found in `ps`, then in `sr`, then among the
 * presets of the catalog in force, and gives nothing when it is in none. Where the second segment
 * of `ct` is the catalog's, a copy of a preset the catalog declares is read as that preset,
 * resolved already, and its definition is not read.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for what it reads that is not in its form: `nt`, `pm`,
 * `ps` or `sr` of another type, `pl` of another type where an item names a place, a role name an
 * entry is found under that is not a token, an entry or an item looked up, the permission looked
 * up twice in `pm`, a definition resolved. A name in both `ps` and `sr` is read as the copy.
 */
export function readSet(
  catalog: CompiledCatalog,
  head: GrantsHead,
  asked: AskedOfGrants,
): Omit<Decision, "covered"> {
  const { grants } = head;
  const { permission } = asked;
  const nt = ownRecord(grants, "nt");
  if (!nt) throw shapeError(nt);
  const pm = ownList(grants, "pm");
  const ps = ownRecord(grants, "ps");
  const sr = ownRecord(grants, "sr");
  const chain = new Set(chainOf(asked.place));
  const placeOf = placesOf(grants);
  const applies = (item: GrantsItemRead<unknown>): item is GrantsItemRead =>
    isLive(item.end, asked.time) && typeof item.place === "string" && chain.has(item.place);

  const blocks = blocking(catalog, permission);
  const reaches = down(catalog, permission);
  const satisfying = wanted(catalog, permission);
  const positions = pm ? positionsOf(pm, blocks, reaches) : undefined;
  const read = new Map<string, EntryRead | undefined>();
  const entryOf = (name: string, isValue: boolean) => {
    if (read.has(name)) return read.get(name);
    const entry = own(nt, name);
    const items =
      entry === undefined ? undefined : readEntry(readEntryMembers(entry, isValue), placeOf);
    read.set(name, items);
    return items;
  };
  const itemsOf = (permissions: ReadonlySet<string>, member: "a" | "d" | "x") => {
    const out: { value: string; item: GrantsItemRead }[] = [];
    for (const value of spelled(permissions)) {
      const name = positions && !value.includes("*") ? positions.get(value) : value;
      const entry = name === undefined ? undefined : entryOf(name, true);
      for (const item of entry?.[member] ?? []) if (applies(item)) out.push({ value, item });
    }
    return out;
  };

  const denies = itemsOf(blocks, "d");
  const exclusions = itemsOf(reaches, "x").map(({ value, item }) => ({
    item,
    taken: removed(catalog, value),
  }));
  const given = itemsOf(satisfying, "a");
  const roles = [...roleNames(catalog, ps, sr)].flatMap((name) => {
    if (!Object.hasOwn(nt, name)) return [];
    if (!isToken(name)) throw shapeError(name);
    const items = (entryOf(name, false)?.a ?? []).filter(applies);
    return items.length > 0 ? [{ name, items }] : [];
  });

  const [deny] = denies;
  if (deny) return { allowed: false, by: byOf("deny", deny.value, deny.item) };
  const allowing = (items: readonly GrantsItemRead[], gives: ReadonlySet<string>) =>
    items.find((item) =>
      [...satisfying].some(
        (permitted) =>
          gives.has(permitted) &&
          !exclusions.some(
            (exclusion) =>
              covers(item.place, exclusion.item.place) &&
              exclusion.taken.has(permitted) &&
              (exclusion.item.bundle === undefined || exclusion.item.bundle === item.bundle),
          ),
      ),
    );
  for (const { value, item } of given) {
    if (allowing([item], expand(catalog, value))) {
      return { allowed: true, by: byOf("allow", value, item) };
    }
  }
  const samePresets = segmentOf(head.ct) === segmentOf(catalog.fingerprint);
  const reader = readerOver(catalog, definitionsOf(catalog, { pm, ps, sr, samePresets }));
  for (const { name, items } of roles) {
    const item = allowing(items, reader.resolve(name).gives);
    if (item) return { allowed: true, by: byOf("assign", name, item) };
  }
  return { allowed: false };
}

/**
 * The role names whose entries a read tries: those of `ps`, then of `sr`, then the presets of the
 * catalog, each once. Their form is checked once an entry is found under one.
 */
function roleNames(
  catalog: CompiledCatalog,
  ps: Record<string, unknown> | undefined,
  sr: Record<string, unknown> | undefined,
): Set<string> {
  return new Set([...Object.keys(ps ?? {}), ...Object.keys(sr ?? {}), ...catalog.presets.keys()]);
}

/** Every item of a checked entry, by member, each place found by `placeOf`. */
function readEntry(entry: Record<string, unknown>, placeOf: PlaceOf<unknown>): EntryRead {
  return {
    a: readItems(entry, "a", placeOf),
    d: readItems(entry, "d", placeOf),
    x: readItems(entry, "x", placeOf),
  };
}

type EntryRead = Record<"a" | "d" | "x", GrantsItemRead<unknown>[]>;

/**
 * Where a read finds a role by name: a copy in `ps`, then a stored role in `sr`, each definition
 * read once it is asked for, then a preset of the catalog in force. With `samePresets`, the
 * presets of issue are the catalog's, so a copy of a preset the catalog declares is that preset,
 * already resolved, and the copy is not read.
 */
function definitionsOf(
  catalog: CompiledCatalog,
  tables: {
    readonly pm: readonly unknown[] | undefined;
    readonly ps: Record<string, unknown> | undefined;
    readonly sr: Record<string, unknown> | undefined;
    readonly samePresets: boolean;
  },
) {
  const { pm, ps, sr, samePresets } = tables;
  const permissionAt = (index: number) => {
    const permission = pm?.[index];
    return isPermission(permission) ? permission : undefined;
  };
  const read = new Map<string, StoredRole>();
  return (name: string) => {
    const copied = ps !== undefined && Object.hasOwn(ps, name);
    if (copied && samePresets) {
      const preset = catalog.presets.get(name);
      if (preset) return preset;
    }
    const table = copied ? ps : sr && Object.hasOwn(sr, name) ? sr : undefined;
    if (!table) return catalog.presets.get(name);
    let role = read.get(name);
    if (!role) {
      role = { name, entries: readDefinition(name, table[name], permissionAt) };
      read.set(name, role);
    }
    return role;
  };
}

/**
 * The places of `pl` an item points at, read one at a time and never checked: `"/"` for no index.
 * An index `pl` does not hold is malformed, and so is a `pl` that is not a list.
 */
function placesOf(grants: Record<string, unknown>): PlaceOf<unknown> {
  return (index, item) => {
    if (index === undefined) return "/";
    const pl = ownList(grants, "pl");
    if (!pl || index >= pl.length) throw shapeError(item);
    return pl[index];
  };
}

/**
 * The position in `pm` of each concrete permission of `values`, read in one pass. A permission
 * found twice is malformed: an entry under either position would be missed.
 */
function positionsOf(
  pm: readonly unknown[],
  blocks: ReadonlySet<string>,
  reaches: ReadonlySet<string>,
): Map<string, string> {
  const out = new Map<string, string>();
  for (let index = 0; index < pm.length; index++) {
    const permission = pm[index];
    if (typeof permission !== "string") continue;
    if (!blocks.has(permission) && !reaches.has(permission)) continue;
    if (out.has(permission)) throw shapeError(permission);
    out.set(permission, String(index));
  }
  return out;
}

/** The spellings of `permissions`, each once, in their order: the permission itself first. */
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

function segmentOf(fingerprint: string): string {
  return fingerprint.slice(fingerprint.indexOf(".") + 1);
}
