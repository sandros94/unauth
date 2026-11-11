import { catalogInvalid } from "./errors.ts";

/** Catalog data checked for shape: the members the model defines, lists of strings, nothing else. */
export interface PlainCatalogData {
  readonly permissions: readonly string[];
  readonly implies?: Readonly<Record<string, readonly string[]>>;
  readonly presets?: Readonly<Record<string, readonly string[]>>;
  readonly places?: false | Readonly<Record<string, readonly string[]>>;
  readonly manager?: string;
  readonly assigner?: Readonly<Record<string, string>>;
}

/**
 * A frozen copy of `input` when it is catalog data in shape: a plain object holding only the six
 * members, each list a list of strings and each map a plain object. Absent `permissions` reads as
 * none. Anything else is `ERR_AUTHZ_CATALOG_INVALID`. The values themselves are checked when the
 * copy is compiled.
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
    manager?: string;
    assigner?: Readonly<Record<string, string>>;
  } = { permissions: data.permissions === undefined ? [] : list(data.permissions, "permissions") };
  if (data.implies !== undefined) copy.implies = listMap(data.implies, "implies");
  if (data.presets !== undefined) copy.presets = listMap(data.presets, "presets");
  if (data.places !== undefined) {
    copy.places = data.places === false ? false : listMap(data.places, "places");
  }
  if (data.manager !== undefined) {
    if (typeof data.manager !== "string") throw shapeError("manager");
    copy.manager = data.manager;
  }
  if (data.assigner !== undefined) {
    const source = plainObject(data.assigner, "assigner");
    const assigner: Record<string, string> = {};
    for (const [name, permission] of Object.entries(source)) {
      if (typeof permission !== "string") throw shapeError(`assigner.${name}`);
      define(assigner, name, permission);
    }
    copy.assigner = Object.freeze(assigner);
  }
  return Object.freeze(copy);
}

const MEMBERS: ReadonlySet<string> = new Set([
  "permissions",
  "implies",
  "presets",
  "places",
  "manager",
  "assigner",
]);

function plainObject(value: unknown, at: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw shapeError(at);
  const prototype: unknown = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) throw shapeError(at);
  const record: Record<string, unknown> = {};
  for (const [key, member] of Object.entries(value)) define(record, key, member);
  return record;
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
  const out: Record<string, readonly string[]> = {};
  for (const [name, items] of Object.entries(source))
    define(out, name, list(items, `${at}.${name}`));
  return Object.freeze(out);
}

function define<T>(target: Record<string, T>, key: string, value: T): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function shapeError(at: string) {
  return catalogInvalid("The catalog is not catalog data.", { reason: "shape", at });
}
