import { compileCatalog, rememberCompiled, readCatalogData } from "./_internal/compile.ts";

/** A permission, or a wildcard over the declared ones: `report:*`, `*:read`, `*`. */
export type PermissionPattern<TPermission extends string = string> =
  | TPermission
  | "*"
  | (TPermission extends `${infer TResource}:${infer TAction}`
      ? `${TResource}:*` | `*:${TAction}`
      : never);

/** One entry of a role: a permission pattern, the name of a role, or either one excluded with `-`. */
export type RoleEntry<TPermission extends string = string, TRole extends string = string> =
  | PermissionPattern<TPermission>
  | TRole
  | `-${PermissionPattern<TPermission> | TRole}`;

/**
 * The vocabulary of an application, in the shape the model gives it: this object is what the
 * fingerprint is computed over, so it is the same data in every language.
 */
export interface CatalogData<TPermission extends string = string, TPreset extends string = string> {
  /** Every permission the application recognises, each `resource:action`. */
  permissions: readonly TPermission[];
  /** What a permission includes: `{ "report:write": ["report:read"] }`. */
  implies?: { readonly [K in NoInfer<TPermission>]?: readonly NoInfer<TPermission>[] };
  /**
   * Roles defined in code. An entry is a declared permission, a wildcard over declared ones, the
   * name of another preset, or any of those prefixed with `-` to exclude it.
   */
  presets?: {
    readonly [K in TPreset]: readonly RoleEntry<NoInfer<TPermission>, NoInfer<TPreset>>[];
  };
  /**
   * The structure of places, all or nothing.
   * - an object: which level may sit under which. The key is a level, `/` for the root, or `*` for
   *   the root and every level. A place that does not fit is refused.
   * - `false`: the application has no places, and every place but the root is refused.
   * - absent: places are not checked beyond their grammar.
   */
  places?: false | Record<string, readonly string[]>;
}

/** A catalog the engine checked. Hand it as the first argument to every function of `unauth/z`. */
export interface Catalog<TPermission extends string = string, TPreset extends string = string> {
  readonly data: CatalogData<TPermission, TPreset>;
  /** Equal for two catalogs that declare the same things. Grants carry it. */
  readonly fingerprint: string;
}

/**
 * Checks a catalog and computes its fingerprint. The permissions and presets it declares are
 * captured as types: a misspelled permission does not compile, in the catalog's own entries or in
 * a question asked later.
 *
 * @throws `ERR_AUTHZ_CATALOG_INVALID` for a member the model does not define, a permission
 * declared twice, a name that is not a lowercase token, an implication between undeclared
 * permissions or in a cycle, a preset that does not resolve, or `places` that declare no level or
 * put a level under one that sits nowhere.
 *
 * @example
 * export const catalog = defineCatalog({
 *   permissions: ["report:read", "report:write", "access:manage"],
 *   implies: { "report:write": ["report:read"] },
 *   presets: { viewer: ["report:read"], owner: ["*"] },
 * });
 */
export function defineCatalog<
  const TPermission extends string,
  const TPreset extends string = never,
>(data: CatalogData<TPermission, TPreset>): Catalog<TPermission, TPreset> {
  const copy = readCatalogData(data);
  const compiled = compileCatalog(copy);
  const catalog: Catalog<TPermission, TPreset> = Object.freeze({
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- a frozen copy of `data`, member for member, checked against the same catalog
    data: copy as CatalogData<TPermission, TPreset>,
    fingerprint: compiled.fingerprint,
  });
  rememberCompiled(catalog, compiled);
  return catalog;
}
