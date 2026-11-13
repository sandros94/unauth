import { isRecord } from "../../_internal/shared.ts";
import type { CompiledCatalog, PlainCatalogData } from "./compiled.ts";
import { catalogInvalid } from "./errors.ts";
import { catalogFingerprint } from "./fingerprint.ts";
import { isPermission } from "./grammar.ts";
import { closeImplications } from "./implications.ts";
import { resolvePresets } from "./presets.ts";
import { compileStructure } from "./structure.ts";

/** The public face of a catalog: its data and the fingerprint computed over it. */
export interface CatalogLike {
  readonly data: unknown;
  readonly fingerprint: unknown;
}

/**
 * Checks catalog data, checked for shape already, against every rule on catalogs and compiles it.
 * Throws `ERR_AUTHZ_CATALOG_INVALID` naming the first rule broken.
 */
export function compileCatalog(data: PlainCatalogData): CompiledCatalog {
  const permissions = new Set<string>();
  const byResource = new Map<string, Set<string>>();
  const byAction = new Map<string, Set<string>>();
  for (const permission of data.permissions) {
    if (!isPermission(permission)) throw invalid("token", "permissions", permission);
    if (permissions.has(permission)) throw invalid("duplicate", "permissions", permission);
    permissions.add(permission);
    const colon = permission.indexOf(":");
    addTo(byResource, permission.slice(0, colon), permission);
    addTo(byAction, permission.slice(colon + 1), permission);
  }

  const direct = new Map<string, Set<string>>();
  for (const [from, targets] of Object.entries(data.implies ?? {})) {
    if (!permissions.has(from)) throw invalid("implication", "implies", from);
    for (const target of targets) {
      if (!permissions.has(target)) throw invalid("implication", `implies.${from}`, target);
      addTo(direct, from, target);
    }
  }
  const { implies, impliedBy } = closeImplications(direct);

  const base: CompiledCatalog = {
    fingerprint: catalogFingerprint(data),
    permissions,
    byResource,
    byAction,
    implies,
    impliedBy,
    presets: new Map(),
    presetEntries: new Map(Object.entries(data.presets ?? {})),
    structure: compileStructure(data.places),
  };
  return Object.freeze({ ...base, presets: resolvePresets(base, data.presets) });
}

/**
 * The compiled form of a catalog. A catalog `defineCatalog` returned is found at once; any other
 * object is checked and compiled on first use, and refused with `ERR_AUTHZ_CATALOG_INVALID` when
 * its data breaks a rule or its fingerprint is not the one its data gives.
 */
export function compiledOf(catalog: CatalogLike): CompiledCatalog {
  const known = compiled.get(catalog);
  if (known) return known;
  if (!isRecord(catalog)) {
    throw catalogInvalid("The catalog is not catalog data.", { reason: "shape", at: "catalog" });
  }
  const result = compileCatalog(readCatalogData(catalog.data));
  if (result.fingerprint !== catalog.fingerprint) {
    throw catalogInvalid("The catalog's fingerprint does not match its data.", {
      reason: "fingerprint",
      at: "fingerprint",
      value: catalog.fingerprint,
    });
  }
  compiled.set(catalog, result);
  return result;
}

/** Records the compiled form of a catalog built from it, so {@link compiledOf} finds it at once. */
export function rememberCompiled(catalog: CatalogLike, result: CompiledCatalog): void {
  compiled.set(catalog, result);
}

const compiled = new WeakMap<object, CompiledCatalog>();

const MESSAGES = {
  token: "The catalog names a permission that is not two tokens joined by a colon.",
  duplicate: "The catalog declares a permission twice.",
  implication: "An implication names a permission the catalog does not declare.",
} as const;

/**
 * A frozen copy of `input` when it is catalog data in shape: a plain object holding only the four
 * members the model defines, each list a list of strings and each map a plain object. Absent
 * `permissions` reads as none. Anything else is `ERR_AUTHZ_CATALOG_INVALID` (`shape`), with `at`
 * naming a member the model does not define. The values themselves are checked when the copy is
 * compiled.
 */
export function readCatalogData(input: unknown): PlainCatalogData {
  const data = plainObject(input, "catalog");
  for (const member of Object.keys(data)) {
    if (!MEMBERS.has(member)) throw shapeError(member);
  }
  const copy: {
    permissions: readonly string[];
    implies?: Readonly<Record<string, readonly string[]>>;
    presets?: Readonly<Record<string, readonly string[]>>;
    places?: false | Readonly<Record<string, readonly string[]>>;
  } = { permissions: data.permissions === undefined ? [] : list(data.permissions, "permissions") };
  if (data.implies !== undefined) copy.implies = listMap(data.implies, "implies");
  if (data.presets !== undefined) copy.presets = listMap(data.presets, "presets");
  if (data.places !== undefined) {
    copy.places = data.places === false ? false : listMap(data.places, "places");
  }
  return Object.freeze(copy);
}

function invalid(reason: keyof typeof MESSAGES, at: string, value: unknown) {
  return catalogInvalid(MESSAGES[reason], { reason, at, value });
}

function addTo(map: Map<string, Set<string>>, key: string, value: string): void {
  const set = map.get(key);
  if (set) set.add(value);
  else map.set(key, new Set([value]));
}

const MEMBERS: ReadonlySet<string> = new Set(["permissions", "implies", "presets", "places"]);

function plainObject(value: unknown, at: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw shapeError(at);
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw shapeError(at);
  return Object.fromEntries(Object.entries(value));
}

function list(value: unknown, at: string): readonly string[] {
  if (!Array.isArray(value)) throw shapeError(at);
  const out: string[] = [];
  for (let index = 0; index < value.length; index++) {
    const item: unknown = value[index];
    if (typeof item !== "string") throw shapeError(at);
    out.push(item);
  }
  return Object.freeze(out);
}

function listMap(value: unknown, at: string): Readonly<Record<string, readonly string[]>> {
  const source = plainObject(value, at);
  return Object.freeze(
    Object.fromEntries(
      Object.entries(source).map(([name, items]) => [name, list(items, `${at}.${name}`)]),
    ),
  );
}

function shapeError(at: string) {
  return catalogInvalid("The catalog is not catalog data.", { reason: "shape", at });
}
