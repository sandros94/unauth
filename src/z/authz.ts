import { isRecord } from "../_internal/shared.ts";
import { type AskOptions, ask } from "./ask.ts";
import { compiledOf } from "./_internal/compile.ts";
import { type Catalog, type CatalogData, defineCatalog } from "./catalog.ts";
import {
  type CouldOptions,
  type DivergedOptions,
  type IssueGrantsOptions,
  type RolesOfOptions,
  could,
  diverged,
  issueGrants,
  rolesOf,
} from "./grants.ts";
import { placeFits } from "./place.ts";
import { type RelatedValues, relatedValues } from "./relate.ts";
import { type ResolveRoleOptions, resolveRole } from "./roles.ts";
import type {
  Decision,
  Diverged,
  Grants,
  GrantsPart,
  Question,
  Statement,
  SubjectStatements,
  ValidationIssue,
} from "./types.ts";
import {
  type ValidateRoleOptions,
  type ValidateStatementOptions,
  validateRole,
  validateStatement,
} from "./validate.ts";

/**
 * The engine with its catalog given once: the functions of `unauth/z` that take a catalog first,
 * as methods without it. It holds the catalog and the default `omit` of `issueGrants`, nothing else.
 * Where statements are stored, how
 * grants are carried and which queries read them stay the application's. The assertions,
 * `assertGrants`, `assertStatement` and `assertRole`, are not among them: an assertion cannot
 * narrow through a method of an inferred constant, so they are used as
 * `assertGrants(authz.catalog, value)`.
 */
export interface Authz<TPermission extends string = string, TPreset extends string = string> {
  /** The checked catalog, for the functions used on their own. */
  readonly catalog: Catalog<TPermission, TPreset>;
  /** See {@link ask}. */
  ask<TStatement extends Statement>(
    read: SubjectStatements<TStatement>,
    question: Question<TPermission>,
    options?: AskOptions,
  ): Decision<TStatement>;
  /** See {@link could}. */
  could(
    grants: unknown,
    question: Question<TPermission>,
    options?: CouldOptions,
  ): Decision<Omit<Statement, "subject">>;
  /** See {@link diverged}. */
  diverged(grants: unknown, options?: DivergedOptions): Diverged | undefined;
  /** See {@link rolesOf}. */
  rolesOf(grants: unknown, question?: Pick<Question, "place">, options?: RolesOfOptions): string[];
  /**
   * See {@link issueGrants}. `omit` defaults to the one given to {@link defineAuthz}, and one given
   * here replaces it.
   */
  issueGrants(read: SubjectStatements, options?: IssueGrantsOptions): Grants;
  /** See {@link validateStatement}. */
  validateStatement(value: unknown, options?: ValidateStatementOptions): ValidationIssue[];
  /** See {@link validateRole}. */
  validateRole(value: unknown, options?: ValidateRoleOptions): ValidationIssue[];
  /** See {@link resolveRole}. */
  resolveRole(name: string, options?: ResolveRoleOptions): TPermission[];
  /** See {@link relatedValues}. */
  relatedValues(permission: TPermission): RelatedValues;
  /** See {@link placeFits}. */
  placeFits(key: string): boolean;
}

/**
 * The permissions of a catalog, from {@link defineCatalog}, or of an engine, from
 * {@link defineAuthz}: `type Permission = PermissionOf<typeof catalog>`. Anything else, the data of
 * a catalog included, does not compile.
 */
export type PermissionOf<T extends Catalog | Authz> =
  T extends Catalog<infer TPermission, infer _TPreset>
    ? TPermission
    : T extends Authz<infer TPermission, infer _TPreset>
      ? TPermission
      : never;

/**
 * The presets of a catalog, from {@link defineCatalog}, or of an engine, from {@link defineAuthz}:
 * `type Preset = PresetOf<typeof catalog>`. Anything else, the data of a catalog included, does not
 * compile.
 */
export type PresetOf<T extends Catalog | Authz> =
  T extends Catalog<infer _TPermission, infer TPreset>
    ? TPreset
    : T extends Authz<infer _TPermission, infer TPreset>
      ? TPreset
      : never;

/** Options of {@link defineAuthz}. */
export interface AuthzOptions {
  /** What the bound `issueGrants` omits when a call names nothing: see {@link IssueGrantsOptions}. */
  omit?: readonly GrantsPart[];
}

/**
 * Returns the engine bound to a catalog: the same functions as `unauth/z` exports, with the
 * catalog already given. Takes catalog data, which it checks as {@link defineCatalog} does, or a
 * catalog already defined, which it binds as it is: one catalog, defined once in code that the
 * server and the client share, then serves both.
 *
 * It binds every function of the engine, so a bundler cannot drop the ones a caller does not use.
 * A client that only reads, a browser showing or hiding things, imports the functions it needs and
 * passes the catalog itself: `could(catalog, grants, question)`.
 *
 * @throws `ERR_AUTHZ_CATALOG_INVALID` as {@link defineCatalog} does, and for a catalog whose
 * fingerprint is not the one its data gives.
 *
 * @example
 * export const authz = defineAuthz({
 *   permissions: ["report:read", "report:write", "access:manage"],
 *   presets: { viewer: ["report:read"], owner: ["*"] },
 * });
 *
 * const { allowed, diverged } = authz.could(session.data.grants, { permission: "report:write" });
 * if (!allowed) throw forbidden();
 *
 * @example
 * export const catalog = defineCatalog({ permissions: ["report:read"] });
 * export const authz = defineAuthz(catalog);
 */
export function defineAuthz<TPermission extends string, TPreset extends string>(
  catalog: Catalog<TPermission, TPreset>,
  defaults?: AuthzOptions,
): Authz<TPermission, TPreset>;
export function defineAuthz<const TPermission extends string, const TPreset extends string = never>(
  data: CatalogData<TPermission, TPreset>,
  defaults?: AuthzOptions,
): Authz<TPermission, TPreset>;
export function defineAuthz<TPermission extends string, TPreset extends string>(
  source: Catalog<TPermission, TPreset> | CatalogData<TPermission, TPreset>,
  defaults?: AuthzOptions,
): Authz<TPermission, TPreset> {
  const catalog = isCatalog(source) ? source : defineCatalog(source);
  compiledOf(catalog);
  const omit = defaults?.omit;
  return {
    catalog,
    ask: (read, question, options) => ask(catalog, read, question, options),
    could: (grants, question, options) => could(catalog, grants, question, options),
    diverged: (grants, options) => diverged(catalog, grants, options),
    rolesOf: (grants, question, options) => rolesOf(catalog, grants, question, options),
    issueGrants: (read, options) =>
      issueGrants(catalog, read, { ...options, omit: options?.omit ?? omit }),
    validateStatement: (value, options) => validateStatement(catalog, value, options),
    validateRole: (value, options) => validateRole(catalog, value, options),
    resolveRole: (name, options) => resolveRole(catalog, name, options),
    relatedValues: (permission) => relatedValues(catalog, permission),
    placeFits: (key) => placeFits(catalog, key),
  };
}

function isCatalog<TPermission extends string, TPreset extends string>(
  source: Catalog<TPermission, TPreset> | CatalogData<TPermission, TPreset>,
): source is Catalog<TPermission, TPreset> {
  return isRecord(source) && "fingerprint" in source && "data" in source;
}
