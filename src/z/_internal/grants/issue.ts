import type { Grants, GrantsEntry, GrantsItem, GrantsRoleEntry, StoredRole } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import { compareBytes, isPermission, readEntry, sortedUnique } from "../grammar.ts";
import { covers } from "../keys.ts";
import { type RoleBreak, entryMalformed, referenceBreak } from "../roles.ts";
import type { ReadStatement } from "../statements.ts";
import { isLive } from "../time.ts";

/**
 * Who grants are issued for, where, when and how. `subject` tells the statements about it from
 * those about its groups, `bases` are canonical keys that fit the catalog, `copies` whether presets
 * travel as copies or by name.
 */
export interface IssueInput {
  readonly subject: string;
  readonly bases: readonly string[];
  readonly time: number;
  readonly copies: boolean;
}

/**
 * Writes the grants of a subject from the statements that apply to it, as the model issues them:
 * those live at `time`, on the chain of a base or under one, each at its own place and as written,
 * inert ones included. Only an assignment of a role that cannot be resolved is left out: a role
 * that is neither a preset nor in `stored`, one that references such a role, with or without `-`,
 * directly or through others, and one on a cycle of references. Roles are frozen at issue, so no
 * later read would resolve it either. A role that resolves but gives nothing is kept. Roles are
 * resolved only to tell that: the definitions of every role assigned, and of every role those
 * reference, are written as they are, a stored role in `sr` and a preset in `ps` when
 * presets travel as copies. With a definition and a concrete permission named, `pm` holds every
 * concrete permission once, and entries and definitions name each by its position. Each group, any
 * subject but `subject`, with an exclusion kept gets a bundle, numbered by the byte order of the
 * groups. Tables, definitions, entries and items are sorted, so the same input writes the same
 * object.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`entry`) for a stored role assigned, or reached from one, whose
 * entry is not in its form.
 */
export function issueSet(
  catalog: CompiledCatalog,
  stored: ReadonlyMap<string, StoredRole>,
  statements: readonly ReadStatement[],
  input: IssueInput,
): Grants {
  const { subject, time } = input;
  const bases = widest(input.bases);
  const find = (name: string) => catalog.presets.get(name) ?? stored.get(name);
  const checked = new Map<StoredRole, RoleBreak | undefined>();
  const resolves = (name: string) => {
    if (catalog.presets.has(name)) return true;
    const role = stored.get(name);
    return role !== undefined && referenceBreak(find, role, checked) === undefined;
  };
  const kept: ReadStatement[] = [];
  for (const statement of statements) {
    if (!isLive(statement.expiresAt, time)) continue;
    const { place, kind, value } = statement;
    if (!bases.some((base) => covers(place, base) || covers(base, place))) continue;
    if (kind === "assign" && !resolves(value)) continue;
    kept.push(statement);
  }
  const assigned = kept.filter(({ kind }) => kind === "assign").map(({ value }) => value);
  const { ps, sr } = definitionsOf(catalog, stored, assigned, input.copies);

  const bundled = sortedUnique(
    kept
      .filter((statement) => statement.kind === "exclude" && statement.subject !== subject)
      .map((statement) => statement.subject),
  );
  const bundleOf = new Map(bundled.map((group, index) => [group, index + 1]));
  const places = sortedUnique(kept.map((statement) => statement.place).filter(notRoot));
  const placeIndex = new Map(places.map((place, index) => [place, index]));
  const defined = [...ps, ...sr].flatMap(([, entries]) => entries);
  const named = [...kept.map(({ value }) => value), ...defined.map(unprefixed)].filter(
    isPermission,
  );
  const table = ps.size + sr.size > 0 && named.length > 0 ? sortedUnique(named) : undefined;
  const position = new Map(table?.map((permission, index) => [permission, index]));

  const byName = new Map<string, Record<Member, GrantsItem[]>>();
  for (const statement of kept) {
    const { value, kind } = statement;
    const name = String(position.get(value) ?? value);
    let entry = byName.get(name);
    if (!entry) byName.set(name, (entry = { a: [], d: [], x: [] }));
    const member = MEMBERS[kind];
    const bundle =
      member === "d" || statement.subject === subject ? undefined : bundleOf.get(statement.subject);
    entry[member].push(itemOf(placeIndex.get(statement.place), statement.expiresAt, bundle));
  }

  const nt: Record<string, GrantsEntry> = {};
  for (const [name, items] of [...byName].toSorted(([a], [b]) => compareBytes(a, b))) {
    const entry: GrantsEntry = {};
    for (const member of ["a", "d", "x"] as const) {
      if (items[member].length > 0) entry[member] = sortedItems(items[member]);
    }
    nt[name] = entry;
  }
  const written = (definitions: Map<string, string[]>) =>
    Object.fromEntries(
      [...definitions]
        .toSorted(([a], [b]) => compareBytes(a, b))
        .map(([name, entries]) => [name, entries.map((entry) => positioned(entry, position))]),
    );
  return {
    v: "1",
    ct: catalog.fingerprint,
    at: time,
    ...(!(bases.length === 1 && bases[0] === "/") && { bs: bases }),
    ...(places.length > 0 && { pl: places }),
    ...(table && { pm: table }),
    ...(ps.size > 0 && { ps: written(ps) }),
    ...(sr.size > 0 && { sr: written(sr) }),
    nt,
  };
}

type Member = "a" | "d" | "x";

const MEMBERS = { allow: "a", assign: "a", deny: "d", exclude: "x" } as const;

/**
 * The definitions to write, entries as written in the role, sorted by bytes, each once: of every
 * role in `assigned` and every role they reference, directly or through others. A name that is a
 * preset is the preset, written in `ps` with `copies` and not at all without. A name that is
 * neither a preset nor in `stored` has no definition to write.
 */
function definitionsOf(
  catalog: CompiledCatalog,
  stored: ReadonlyMap<string, StoredRole>,
  assigned: readonly string[],
  copies: boolean,
): { ps: Map<string, string[]>; sr: Map<string, string[]> } {
  const ps = new Map<string, string[]>();
  const sr = new Map<string, string[]>();
  const seen = new Set<string>();
  const queue = [...assigned];
  for (let name = queue.pop(); name !== undefined; name = queue.pop()) {
    if (seen.has(name)) continue;
    seen.add(name);
    const preset = catalog.presetEntries.get(name);
    const role = preset ? undefined : stored.get(name);
    if ((preset && !copies) || (!preset && !role)) continue;
    const entries = sortedUnique(preset ?? role?.entries ?? []);
    for (const entry of entries) {
      const parts = readEntry(entry);
      if (!parts) throw entryMalformed(entry);
      if (parts.kind === "role") queue.push(parts.name);
    }
    (preset ? ps : sr).set(name, entries);
  }
  return { ps, sr };
}

function positioned(entry: string, position: ReadonlyMap<string, number>): GrantsRoleEntry {
  const excluded = entry.startsWith("-");
  const at = position.get(unprefixed(entry));
  if (at === undefined) return entry;
  return excluded ? `-${at}` : at;
}

function unprefixed(entry: string): string {
  return entry.startsWith("-") ? entry.slice(1) : entry;
}

/** The bases once each, sorted, a base under another one left out: it adds nothing. */
function widest(bases: readonly string[]): string[] {
  const unique = sortedUnique(bases);
  return unique.filter((base) => !unique.some((other) => other !== base && covers(other, base)));
}

function notRoot(place: string): boolean {
  return place !== "/";
}

function itemOf(
  place: number | undefined,
  end: number | undefined,
  bundle: number | undefined,
): GrantsItem {
  const item: GrantsItem = [place ?? null, end ?? null, bundle ?? null];
  while (item.length > 0 && item.at(-1) === null) item.pop();
  return item;
}

function sortedItems(items: readonly GrantsItem[]): GrantsItem[] {
  const unique = new Map(items.map((item) => [JSON.stringify(item), item]));
  return [...unique.values()].toSorted(compareItems);
}

function compareItems(a: GrantsItem, b: GrantsItem): number {
  for (let index = 0; index < 3; index++) {
    const x = a[index] ?? -1;
    const y = b[index] ?? -1;
    if (x !== y) return x - y;
  }
  return 0;
}
