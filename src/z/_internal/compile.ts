import { isRecord } from "../../_internal/shared.ts";
import { type PlainCatalogData, readCatalogData } from "./catalog-data.ts";
import type { CompiledCatalog } from "./compiled.ts";
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
  const declared = (value: string) => isPermission(value) && permissions.has(value);

  const direct = new Map<string, Set<string>>();
  for (const [from, targets] of Object.entries(data.implies ?? {})) {
    if (!declared(from)) throw invalid("implication", "implies", from);
    for (const target of targets) {
      if (!declared(target)) throw invalid("implication", `implies.${from}`, target);
      addTo(direct, from, target);
    }
  }
  const { implies, impliedBy } = closeImplications(direct);

  if (data.manager !== undefined && !declared(data.manager)) {
    throw invalid("manager", "manager", data.manager);
  }
  const base: CompiledCatalog = {
    fingerprint: catalogFingerprint(data),
    permissions,
    byResource,
    byAction,
    implies,
    impliedBy,
    presets: new Map(),
    manager: data.manager,
    assigner: new Map(),
    structure: compileStructure(data.places),
  };
  const presets = resolvePresets(base, data.presets);

  const assigner = new Map<string, string>();
  for (const [preset, permission] of Object.entries(data.assigner ?? {})) {
    if (!presets.has(preset)) throw invalid("assigner", "assigner", preset);
    if (!declared(permission)) throw invalid("assigner", `assigner.${preset}`, permission);
    assigner.set(preset, permission);
  }
  return Object.freeze({ ...base, presets, assigner });
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
  manager: "The manager is not a permission the catalog declares.",
  assigner: "An assigner names an unknown preset or an undeclared permission.",
} as const;

function invalid(reason: keyof typeof MESSAGES, at: string, value: unknown) {
  return catalogInvalid(MESSAGES[reason], { reason, at, value });
}

function addTo(map: Map<string, Set<string>>, key: string, value: string): void {
  const set = map.get(key);
  if (set) set.add(value);
  else map.set(key, new Set([value]));
}
