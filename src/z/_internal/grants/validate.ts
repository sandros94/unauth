import { isRecord } from "../../../_internal/shared.ts";
import { isPattern, isPermission, isToken } from "../grammar.ts";
import {
  POSITION,
  assertIssued,
  isIndex,
  own,
  ownList,
  basesOf,
  readDefinition,
  readEntryMembers,
  readHead,
  readItems,
  readKeys,
  shapeError,
} from "./form.ts";

/**
 * Checks one set of grants whole, at `time`, in the order the model gives: `v`, then every check
 * of form on the members the model defines, then the time of issue. Members other than those are
 * ignored. What only the catalog does not know is not checked: it is inert when read.
 *
 * @throws `ERR_AUTHZ_GRANTS_FORMAT` for a `v` other than `"1"`.
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for a set that fails any check of form.
 * @throws `ERR_AUTHZ_GRANTS_EARLY` for `time` earlier than `at`.
 */
export function assertGrantsSet(grants: unknown, time: number): void {
  const head = readHead(grants);
  const set = head.grants;
  basesOf(set);
  const pl = own(set, "pl");
  const places = pl === undefined ? [] : readKeys(pl);
  if (places.includes("/")) throw shapeError(pl);
  const table = readTable(ownList(set, "pm"));
  const permissionAt = (index: number) => table?.[index];
  const ps = definitionNames(own(set, "ps"), permissionAt);
  const sr = definitionNames(own(set, "sr"), permissionAt);
  for (const name of ps) if (sr.has(name)) throw shapeError(name);
  const nt = own(set, "nt");
  if (!isRecord(nt)) throw shapeError(nt);
  const placeOf = (index: number | undefined, item: unknown) => {
    if (index !== undefined && index >= places.length) throw shapeError(item);
  };
  for (const name of Object.keys(nt)) {
    const permission = isValue(name, table);
    if (permission === undefined) throw shapeError(name);
    const entry = readEntryMembers(own(nt, name), permission);
    for (const member of MEMBERS) readItems(entry, member, placeOf);
  }
  assertIssued(head, time);
}

/**
 * Checks `pm` whole: canonical permissions, each once. Returns it, `undefined` when absent.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for a table that fails that check.
 */
export function readTable(table: unknown[] | undefined): string[] | undefined {
  if (table === undefined) return undefined;
  const seen = new Set<string>();
  for (const permission of table) {
    if (!isPermission(permission) || seen.has(permission)) throw shapeError(permission);
    seen.add(permission);
  }
  return [...seen];
}

/**
 * Checks `ps` or `sr` whole, every definition read through `permissionAt`. Returns the
 * definitions by name, an empty map when the member is absent.
 *
 * @throws `ERR_AUTHZ_MALFORMED` (`grants`) for a member that is not an object, a name that is not
 * a token, a definition not in its form.
 */
export function readDefinitions(
  definitions: unknown,
  permissionAt: (index: number) => string | undefined,
): Map<string, string[]> {
  const out = new Map<string, string[]>();
  if (definitions === undefined) return out;
  if (!isRecord(definitions)) throw shapeError(definitions);
  for (const name of Object.keys(definitions)) {
    out.set(name, readDefinition(name, own(definitions, name), permissionAt));
  }
  return out;
}

const MEMBERS = ["a", "d", "x"] as const;

function definitionNames(
  definitions: unknown,
  permissionAt: (index: number) => string | undefined,
): Set<string> {
  return new Set(readDefinitions(definitions, permissionAt).keys());
}

/**
 * Whether a name of `nt` is in its form: `true` for a permission or a pattern, `false` for a role
 * name, `undefined` for anything else. A permission is a position where the set holds `pm`, its
 * name where it does not.
 */
function isValue(name: string, table: readonly string[] | undefined): boolean | undefined {
  if (POSITION.test(name)) {
    const index = Number(name);
    return isIndex(index) && table?.[index] !== undefined ? true : undefined;
  }
  if (isPermission(name)) return table ? undefined : true;
  if (isPattern(name)) return true;
  if (isToken(name)) return false;
  return undefined;
}
