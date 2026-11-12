import { isRecord } from "../../../_internal/shared.ts";
import { UnauthError } from "../../../error.ts";
import type { StoredRole } from "../../types.ts";
import type { CompiledCatalog } from "../compiled.ts";
import { malformed } from "../errors.ts";
import { isPattern, isPermission, isToken, readEntry } from "../grammar.ts";
import { isCanonicalKey } from "../keys.ts";
import { type RoleReader, readerOver } from "../roles.ts";
import { MAX_TIME, isTime } from "../time.ts";

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

/**
 * One set of grants, checked whole, its indices resolved. `bases` is `["/"]` without `bs`. An entry
 * named by its position in `pm` is keyed by the permission's name, `roles` the names of the
 * entries that are role names, `reader` resolves those against the definitions the set holds and
 * the catalog in force. `permissions` are the concrete permissions the set names, `copies` the
 * entries of each copy of a preset and `stored` those of each stored role, positions written back
 * as names.
 */
export interface GrantsSetRead {
  readonly ct: string;
  readonly at: number;
  readonly bases: readonly string[];
  readonly entries: ReadonlyMap<string, GrantsEntryRead>;
  readonly roles: readonly string[];
  readonly reader: RoleReader;
  readonly permissions: readonly string[];
  readonly copies: ReadonlyMap<string, readonly string[]>;
  readonly stored: ReadonlyMap<string, readonly string[]>;
}

/**
 * Checks one set of grants handed in, at the time of a read, in the order the model gives: `v`,
 * then every check of form on the members the model defines, then the catalog, then the time of
 * issue. Members other than those are ignored. What only the catalog does not know is not checked:
 * it is inert when read.
 *
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` for a `v` other than `"1"`.
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for a set that fails any check of form.
 * @throws `ERR_AUTHZ_GRANTS_CATALOG` (`presets`) for a set that names a preset it holds no copy of,
 * read under presets other than those it was issued under.
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
  const at = own(grants, "at");
  if (typeof ct !== "string" || !FINGERPRINT.test(ct) || !isTime(at)) throw shapeError(grants);
  const bs = own(grants, "bs");
  const bases = bs === undefined ? ["/"] : readKeys(bs);
  const pl = own(grants, "pl");
  const places = pl === undefined ? [] : readKeys(pl);
  if (places.includes("/")) throw shapeError(pl);
  const pm = own(grants, "pm");
  const table = pm === undefined ? undefined : readTable(pm);
  const ps = readDefinitions(own(grants, "ps"), table);
  const sr = readDefinitions(own(grants, "sr"), table);
  for (const name of ps?.keys() ?? []) if (sr?.has(name)) throw shapeError(name);
  const nt = own(grants, "nt");
  if (!isRecord(nt)) throw shapeError(nt);
  const entries = new Map<string, GrantsEntryRead>();
  const roles: string[] = [];
  for (const name of Object.keys(nt)) {
    const value = valueOf(name, table);
    if (value === undefined) throw shapeError(name);
    if (!value.permission) roles.push(value.name);
    entries.set(value.name, readEntryOf(own(nt, name), { places, permission: value.permission }));
  }

  const named = [
    ...roles,
    ...[...(ps ?? []), ...(sr ?? [])].flatMap(([, role]) => referenced(role)),
  ];
  if (
    !ps &&
    named.some((name) => !sr?.has(name)) &&
    segmentOf(ct) !== segmentOf(catalog.fingerprint)
  ) {
    throw new UnauthError(
      "The grants were issued for another catalog.",
      "ERR_AUTHZ_GRANTS_CATALOG",
      { status: 401, cause: { segment: "presets" } },
    );
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
  const reader = readerOver(
    catalog,
    (name) => ps?.get(name) ?? sr?.get(name) ?? (ps ? undefined : catalog.presets.get(name)),
  );
  return {
    ct,
    at,
    bases,
    entries,
    roles,
    reader,
    permissions: table ?? [...entries.keys()].filter(isPermission),
    copies: new Map([...(ps ?? [])].map(([name, role]) => [name, role.entries])),
    stored: new Map([...(sr ?? [])].map(([name, role]) => [name, role.entries])),
  };
}

function own(record: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(record, name) ? record[name] : undefined;
}

function segmentOf(fingerprint: string): string {
  return fingerprint.slice(fingerprint.indexOf(".") + 1);
}

function readKeys(keys: unknown): string[] {
  if (!Array.isArray(keys)) throw shapeError(keys);
  return keys.map((key: unknown) => {
    if (!isCanonicalKey(key)) throw shapeError(key);
    return key;
  });
}

function readTable(table: unknown): string[] {
  if (!Array.isArray(table)) throw shapeError(table);
  const seen = new Set<string>();
  for (const permission of table) {
    if (!isPermission(permission) || seen.has(permission)) throw shapeError(permission);
    seen.add(permission);
  }
  return [...seen];
}

/**
 * The definitions of `ps` or `sr` as stored roles, every entry written as in the role: a position
 * read back as the permission it names. `undefined` when the member is absent.
 */
function readDefinitions(
  definitions: unknown,
  table: readonly string[] | undefined,
): Map<string, StoredRole> | undefined {
  if (definitions === undefined) return undefined;
  if (!isRecord(definitions)) throw shapeError(definitions);
  const out = new Map<string, StoredRole>();
  for (const name of Object.keys(definitions)) {
    const written = own(definitions, name);
    if (!isToken(name) || !Array.isArray(written)) throw shapeError(name);
    const entries = Array.from(written, (entry: unknown) => {
      const read = roleEntryOf(entry, table);
      if (read === undefined) throw shapeError(entry);
      return read;
    });
    out.set(name, { name, entries });
  }
  return out;
}

function roleEntryOf(entry: unknown, table: readonly string[] | undefined): string | undefined {
  if (typeof entry === "number") return indexed(table ?? [], entry);
  if (typeof entry !== "string") return undefined;
  if (EXCLUDED_POSITION.test(entry)) {
    const permission = table?.[Number(entry.slice(1))];
    return permission === undefined ? undefined : `-${permission}`;
  }
  const parts = readEntry(entry);
  if (!parts || (parts.kind === "pattern" && isPermission(parts.name))) return undefined;
  return entry;
}

function referenced(role: StoredRole): string[] {
  return role.entries.flatMap((entry) => {
    const parts = readEntry(entry);
    return parts?.kind === "role" ? [parts.name] : [];
  });
}

function valueOf(
  name: string,
  table: readonly string[] | undefined,
): { name: string; permission: boolean } | undefined {
  if (POSITION.test(name)) {
    const permission = table?.[Number(name)];
    return permission === undefined ? undefined : { name: permission, permission: true };
  }
  if (isPermission(name)) return table ? undefined : { name, permission: true };
  if (isPattern(name)) return { name, permission: true };
  if (isToken(name)) return { name, permission: false };
  return undefined;
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
  const place = index === undefined ? "/" : indexed(places, index);
  if (place === undefined) throw shapeError(item);
  if (end !== undefined && !isTime(end)) throw shapeError(item);
  if (bundle !== undefined && (deny || !isBundle(bundle))) throw shapeError(item);
  return { place, end, bundle };
}

function indexed(table: readonly string[], index: unknown): string | undefined {
  return typeof index === "number" && Number.isInteger(index) && index >= 0
    ? table[index]
    : undefined;
}

function isBundle(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= MAX_TIME;
}

const FINGERPRINT = /^[A-Za-z0-9_-]{11}\.[A-Za-z0-9_-]{11}$/;
const POSITION = /^(?:0|[1-9][0-9]*)$/;
const EXCLUDED_POSITION = /^-(?:0|[1-9][0-9]*)$/;

function shapeError(value: unknown) {
  return malformed("The grants are not in their one form.", { what: "grants", value });
}
