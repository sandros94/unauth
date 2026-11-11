import { isRecord } from "../../_internal/shared.ts";
import { UnauthError } from "../../error.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { malformed } from "./errors.ts";
import { isPattern } from "./grammar.ts";
import { isCanonicalKey } from "./keys.ts";
import { expand } from "./permissions.ts";
import { fits } from "./structure.ts";
import { MAX_TIME, isTime } from "./time.ts";

/** One item of grants as read: a canonical key, the second it ends, and its bundle. */
export interface GrantsItemRead {
  readonly place: string;
  readonly end: number | undefined;
  readonly bundle: number | undefined;
}

/** One entry of grants as read: what it gives, denies and takes out. */
export interface GrantsEntryRead {
  readonly a: readonly GrantsItemRead[];
  readonly d: readonly GrantsItemRead[];
  readonly x: readonly GrantsItemRead[];
}

/** One set of grants, checked whole, its indices resolved. `bases` is `["/"]` without `bs`. */
export interface GrantsSetRead {
  readonly at: number;
  readonly bases: readonly string[];
  readonly rows: readonly ReadonlySet<string>[];
  readonly entries: ReadonlyMap<string, GrantsEntryRead>;
}

/**
 * Checks one set of grants handed in, at the time of a read, in the order the model gives: `v`,
 * then `ct`, then every check on the members the model defines, then the time of issue. Members
 * other than those are ignored.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for an object without a string `v`, and for a set that
 * fails any check of the grants object.
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` for a `v` other than `"1"`.
 * @throws `ERR_AUTHZ_GRANTS_CATALOG` for a `ct` that is another catalog's fingerprint.
 * @throws `ERR_AUTHZ_GRANTS_EARLY` for `time` earlier than `at`.
 */
export function readGrantsSet(
  catalog: CompiledCatalog,
  grants: unknown,
  time: number,
): GrantsSetRead {
  if (!isRecord(grants)) throw shapeError(grants);
  const v = own(grants, "v");
  if (typeof v !== "string") throw shapeError(grants);
  if (v !== "1") {
    throw new UnauthError("The grants are written in another format.", "ERR_AUTHZ_GRANTS_FORMAT", {
      status: 401,
    });
  }
  const ct = own(grants, "ct");
  if (typeof ct === "string" && ct !== catalog.fingerprint) {
    throw new UnauthError(
      "The grants were issued for another catalog.",
      "ERR_AUTHZ_GRANTS_CATALOG",
      {
        status: 401,
      },
    );
  }
  const at = own(grants, "at");
  if (typeof ct !== "string" || !isTime(at)) throw shapeError(grants);
  const bs = own(grants, "bs");
  const bases = bs === undefined ? ["/"] : readKeys(catalog, bs);
  const pl = own(grants, "pl");
  const places = pl === undefined ? [] : readKeys(catalog, pl);
  if (places.includes("/")) throw shapeError(pl);
  const rl = own(grants, "rl");
  const rows = rl === undefined ? [] : readRows(catalog, rl);
  const nt = own(grants, "nt");
  if (!isRecord(nt)) throw shapeError(nt);
  const entries = new Map<string, GrantsEntryRead>();
  for (const name of Object.keys(nt)) {
    const permission = isNamedPermission(catalog, name);
    if (!permission && !catalog.presets.has(name) && !isRow(name, rows.length)) {
      throw shapeError(name);
    }
    entries.set(name, readEntryOf(own(nt, name), { places, permission }));
  }
  if (time < at) {
    throw new UnauthError(
      "The grants were issued after the time asked.",
      "ERR_AUTHZ_GRANTS_EARLY",
      {
        status: 401,
      },
    );
  }
  return { at, bases, rows, entries };
}

function own(record: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(record, name) ? record[name] : undefined;
}

function readKeys(catalog: CompiledCatalog, keys: unknown): string[] {
  if (!Array.isArray(keys)) throw shapeError(keys);
  return keys.map((key: unknown) => {
    if (!isCanonicalKey(key) || !fits(catalog, key)) throw shapeError(key);
    return key;
  });
}

function readRows(catalog: CompiledCatalog, rows: unknown): Set<string>[] {
  if (!Array.isArray(rows)) throw shapeError(rows);
  return rows.map((row: unknown) => {
    if (!Array.isArray(row)) throw shapeError(row);
    for (const permission of row) {
      if (typeof permission !== "string" || !catalog.permissions.has(permission)) {
        throw shapeError(row);
      }
    }
    return new Set<string>(row);
  });
}

function isNamedPermission(catalog: CompiledCatalog, name: string): boolean {
  return isPattern(name) && expand(catalog, name).size > 0;
}

function isRow(name: string, count: number): boolean {
  return ROW.test(name) && Number(name.slice(1)) < count;
}

function readEntryOf(
  entry: unknown,
  context: { places: readonly string[]; permission: boolean },
): GrantsEntryRead {
  if (!isRecord(entry)) throw shapeError(entry);
  const out: Record<"a" | "d" | "x", GrantsItemRead[]> = { a: [], d: [], x: [] };
  for (const member of Object.keys(entry)) {
    if (member !== "a" && member !== "d" && member !== "x") throw shapeError(entry);
    if (member !== "a" && !context.permission) throw shapeError(entry);
    const items = entry[member];
    if (!Array.isArray(items)) throw shapeError(items);
    out[member] = items.map((item: unknown) => readItem(item, context.places, member === "d"));
  }
  return out;
}

function readItem(item: unknown, places: readonly string[], deny: boolean): GrantsItemRead {
  if (!Array.isArray(item) || item.length > 3) throw shapeError(item);
  const [index, end, bundle]: unknown[] = Array.from(item, (element) => element ?? undefined);
  const place = index === undefined ? "/" : placeAt(places, index);
  if (place === undefined) throw shapeError(item);
  if (end !== undefined && !isTime(end)) throw shapeError(item);
  if (bundle !== undefined && (deny || !isBundle(bundle))) throw shapeError(item);
  return { place, end, bundle };
}

function placeAt(places: readonly string[], index: unknown): string | undefined {
  return typeof index === "number" && Number.isInteger(index) && index >= 0
    ? places[index]
    : undefined;
}

function isBundle(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= MAX_TIME;
}

const ROW = /^#(?:0|[1-9][0-9]*)$/;

function shapeError(value: unknown) {
  return malformed("The grants are not in their one form.", { what: "grants", value });
}
