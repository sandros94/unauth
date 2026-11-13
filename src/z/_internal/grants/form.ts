import { isRecord } from "../../../_internal/shared.ts";
import { UnauthError } from "../../../error.ts";
import { malformed } from "../errors.ts";
import { isPermission, isToken, readEntry } from "../grammar.ts";
import { isCanonicalKey } from "../keys.ts";
import { MAX_TIME, isTime } from "../time.ts";

/** One item of grants as read: its place, the second it ends, and its bundle. */
export interface GrantsItemRead<TPlace = string> {
  readonly place: TPlace;
  readonly end: number | undefined;
  readonly bundle: number | undefined;
}

/**
 * The place of an item from its index, `undefined` for the root: throws `ERR_AUTHZ_MALFORMED` for
 * an index that `pl` does not hold. `item` is the item, for the error.
 */
export type PlaceOf<TPlace> = (index: number | undefined, item: unknown) => TPlace;

/** What every use of a set reads first: the object, its fingerprint and its time of issue. */
export interface GrantsHead {
  readonly grants: Record<string, unknown>;
  readonly ct: string;
  readonly at: number;
}

/**
 * Reads what every use of a set reads first, in the order the model gives: `v`, then `ct` and `at`
 * for their form. Nothing else of the set is looked at.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for a set that is not an object, or a `v`, `ct` or `at`
 * not in its form, and `ERR_AUTHZ_GRANTS_FORMAT` for a `v` other than `"1"`.
 */
export function readHead(grants: unknown): GrantsHead {
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
  return { grants, ct, at };
}

/** `ERR_AUTHZ_GRANTS_EARLY` when `time` is earlier than the issue of `head`. */
export function assertIssued(head: GrantsHead, time: number): void {
  if (time < head.at) {
    throw new UnauthError(
      "The grants were issued after the time asked.",
      "ERR_AUTHZ_GRANTS_EARLY",
      { status: 401 },
    );
  }
}

/** The member `name` of `record` when it is its own, never one reached through its prototype. */
export function own(record: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(record, name) ? record[name] : undefined;
}

/** The member `name` of a set when present, `ERR_AUTHZ_MALFORMED` when it is not an object. */
export function ownRecord(
  record: Record<string, unknown>,
  name: string,
): Record<string, unknown> | undefined {
  const member = own(record, name);
  if (member === undefined) return undefined;
  if (!isRecord(member)) throw shapeError(member);
  return member;
}

/** The member `name` of a set when present, `ERR_AUTHZ_MALFORMED` when it is not a list. */
export function ownList(record: Record<string, unknown>, name: string): unknown[] | undefined {
  const member = own(record, name);
  if (member === undefined) return undefined;
  if (!Array.isArray(member)) throw shapeError(member);
  return member;
}

/** The bases of a set: `["/"]` without `bs`, else every key of `bs`, each canonical. */
export function basesOf(grants: Record<string, unknown>): string[] {
  const bs = own(grants, "bs");
  return bs === undefined ? ["/"] : readKeys(bs);
}

/** A list of canonical keys, `ERR_AUTHZ_MALFORMED` for anything else. */
export function readKeys(keys: unknown): string[] {
  if (!Array.isArray(keys)) throw shapeError(keys);
  return keys.map((key: unknown) => {
    if (!isCanonicalKey(key)) throw shapeError(key);
    return key;
  });
}

/**
 * The checked members of an entry: an object holding `a`, `d` or `x` and nothing else, `d` and `x`
 * only under a permission or a pattern.
 */
export function readEntryMembers(entry: unknown, permission: boolean): Record<string, unknown> {
  if (!isRecord(entry)) throw shapeError(entry);
  for (const member of Object.keys(entry)) {
    if (member !== "a" && member !== "d" && member !== "x") throw shapeError(entry);
    if (member !== "a" && !permission) throw shapeError(entry);
  }
  return entry;
}

/**
 * The items of one member of a checked entry, each in its form and its place found by `placeOf`:
 * `[]` when the member is absent.
 */
export function readItems<TPlace>(
  entry: Record<string, unknown>,
  member: "a" | "d" | "x",
  placeOf: PlaceOf<TPlace>,
): GrantsItemRead<TPlace>[] {
  const items = own(entry, member);
  if (items === undefined) return [];
  if (!Array.isArray(items)) throw shapeError(items);
  return items.map((item: unknown) => readItem(item, member === "d", placeOf));
}

/**
 * A definition of `ps` or `sr`, every entry as written in the role. `ERR_AUTHZ_MALFORMED` for a
 * name that is not a token, a value that is not a list, or an entry not in its form.
 */
export function readDefinition(
  name: string,
  written: unknown,
  permissionAt: (index: number) => string | undefined,
): string[] {
  if (!isToken(name) || !Array.isArray(written)) throw shapeError(name);
  const list: readonly unknown[] = written;
  const entries: string[] = [];
  for (const entry of list) {
    const read = roleEntryOf(entry, permissionAt);
    if (read === undefined) throw shapeError(entry);
    entries.push(read);
  }
  return entries;
}

/** Whether `value` is a position or a place index: an integer from 0. */
export function isIndex(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

/** `ERR_AUTHZ_MALFORMED` (`grants`) for what of grants is not in its one form. */
export function shapeError(value: unknown): UnauthError<"ERR_AUTHZ_MALFORMED"> {
  return malformed("The grants are not in their one form.", { what: "grants", value });
}

/** A position written as text: decimal digits, no sign, no leading zero. */
export const POSITION: RegExp = /^(?:0|[1-9][0-9]*)$/;

const FINGERPRINT = /^[A-Za-z0-9_-]{11}\.[A-Za-z0-9_-]{11}$/;
const EXCLUDED_POSITION = /^-(?:0|[1-9][0-9]*)$/;

function readItem<TPlace>(
  item: unknown,
  deny: boolean,
  placeOf: PlaceOf<TPlace>,
): GrantsItemRead<TPlace> {
  if (!Array.isArray(item) || item.length > 3) throw shapeError(item);
  const index: unknown = item[0] ?? undefined;
  const end: unknown = item[1] ?? undefined;
  const bundle: unknown = item[2] ?? undefined;
  if (index !== undefined && !isIndex(index)) throw shapeError(item);
  const place = placeOf(index, item);
  if (end !== undefined && !isTime(end)) throw shapeError(item);
  if (bundle !== undefined && (deny || !isBundle(bundle))) throw shapeError(item);
  return { place, end, bundle };
}

function isBundle(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 1 && value <= MAX_TIME;
}

function roleEntryOf(
  entry: unknown,
  permissionAt: (index: number) => string | undefined,
): string | undefined {
  if (typeof entry === "number") return isIndex(entry) ? permissionAt(entry) : undefined;
  if (typeof entry !== "string") return undefined;
  if (EXCLUDED_POSITION.test(entry)) {
    const permission = permissionAt(Number(entry.slice(1)));
    return permission === undefined ? undefined : `-${permission}`;
  }
  const parts = readEntry(entry);
  if (!parts || (parts.kind === "pattern" && isPermission(parts.name))) return undefined;
  return entry;
}
