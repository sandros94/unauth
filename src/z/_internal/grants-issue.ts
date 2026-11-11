import type { Grants, GrantsEntry, GrantsItem } from "../types.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { compareBytes, sortedUnique } from "./grammar.ts";
import { covers } from "./keys.ts";
import type { RoleReader } from "./roles.ts";
import { type ReadStatement, isPermanentManager } from "./statements.ts";
import { isLive } from "./time.ts";

/** Who grants are issued for, where and when. `bases` are canonical keys that fit the catalog. */
export interface IssueInput {
  readonly subject: string;
  readonly groups: readonly string[];
  readonly bases: readonly string[];
  readonly time: number;
}

/**
 * Writes the grants of a subject from statements, as the model issues them: the statements about
 * the subject or one of its groups, live at `time`, on the chain of a base or under one, each at
 * its own place. Inert statements were left out when read, and an assignment whose role gives
 * nothing at its place is left out here. A permanent manager's denies and exclusions are left out.
 * Each group with an exclusion kept gets a bundle, numbered by the byte order of the groups.
 * Tables, entries and items are sorted, so the same input writes the same object.
 */
export function issueSet(
  catalog: CompiledCatalog,
  roles: RoleReader,
  statements: readonly ReadStatement[],
  input: IssueInput,
): Grants {
  const { subject, groups, time } = input;
  const bases = widest(input.bases);
  const identifiers = new Set([subject, ...groups]);
  const manager = isPermanentManager(statements, { subject, groups });
  const kept: Kept[] = [];
  for (const statement of statements) {
    if (!identifiers.has(statement.subject) || !isLive(statement.expiresAt, time)) continue;
    const { place } = statement;
    if (!bases.some((base) => covers(place, base) || covers(base, place))) continue;
    if (manager && (statement.kind === "deny" || statement.kind === "exclude")) continue;
    if (statement.kind !== "assign") {
      kept.push({ statement, name: statement.value, member: MEMBERS[statement.kind] });
      continue;
    }
    const gives = roles.resolve(statement.value, place).gives;
    if (gives.size === 0) continue;
    const row = catalog.presets.has(statement.value) ? undefined : sortedUnique(gives);
    kept.push({ statement, name: statement.value, member: "a", row });
  }

  const bundled = sortedUnique(
    kept
      .filter(({ statement }) => statement.kind === "exclude" && statement.subject !== subject)
      .map(({ statement }) => statement.subject),
  );
  const bundleOf = new Map(bundled.map((group, index) => [group, index + 1]));
  const places = sortedUnique(kept.map(({ statement }) => statement.place).filter(notRoot));
  const placeIndex = new Map(places.map((place, index) => [place, index]));
  const rowsByKey = new Map(kept.flatMap(({ row }) => (row ? [[JSON.stringify(row), row]] : [])));
  const rows = [...rowsByKey].toSorted(([a], [b]) => compareBytes(a, b));
  const rowIndex = new Map(rows.map(([key], index) => [key, index]));

  const byName = new Map<string, Record<Member, GrantsItem[]>>();
  for (const { statement, name: value, member, row } of kept) {
    const name = row ? `#${rowIndex.get(JSON.stringify(row))}` : value;
    let entry = byName.get(name);
    if (!entry) byName.set(name, (entry = { a: [], d: [], x: [] }));
    const bundle =
      member === "d" || statement.subject === subject ? undefined : bundleOf.get(statement.subject);
    entry[member].push(
      itemOf(
        statement.place === "/" ? undefined : placeIndex.get(statement.place),
        statement.expiresAt,
        bundle,
      ),
    );
  }

  const nt: Record<string, GrantsEntry> = {};
  for (const [name, items] of [...byName].toSorted(([a], [b]) => compareBytes(a, b))) {
    const entry: GrantsEntry = {};
    for (const member of ["a", "d", "x"] as const) {
      if (items[member].length > 0) entry[member] = sortedItems(items[member]);
    }
    nt[name] = entry;
  }
  return {
    v: "1",
    ct: catalog.fingerprint,
    at: time,
    ...(!(bases.length === 1 && bases[0] === "/") && { bs: bases }),
    ...(places.length > 0 && { pl: places }),
    ...(rows.length > 0 && { rl: rows.map(([, row]) => row) }),
    nt,
  };
}

type Member = "a" | "d" | "x";

interface Kept {
  readonly statement: ReadStatement;
  readonly name: string;
  readonly member: Member;
  readonly row?: string[];
}

const MEMBERS = { allow: "a", deny: "d", exclude: "x" } as const;

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
