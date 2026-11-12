import { ask } from "./ask.ts";
import { type Catalog, type CatalogData, defineCatalog } from "./catalog.ts";
import { type IssueGrantsOptions, could, diverged, issueGrants } from "./grants.ts";
import { placeFits } from "./place.ts";
import { type RelatedValues, relatedValues } from "./relate.ts";
import { type ResolveRoleOptions, resolveRole } from "./roles.ts";
import type {
  Decision,
  Diverged,
  Grants,
  GrantsPart,
  Question,
  QuestionOptions,
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
    options?: QuestionOptions,
  ): Decision<TStatement>;
  /** See {@link could}. */
  could(
    grants: unknown,
    question: Question<TPermission>,
    options?: QuestionOptions,
  ): Decision<Omit<Statement, "subject">>;
  /** See {@link diverged}. */
  diverged(grants: unknown, options?: QuestionOptions): Diverged | undefined;
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

/** Options of {@link defineAuthz}. */
export interface AuthzOptions {
  /** What the bound `issueGrants` omits when a call names nothing: see {@link IssueGrantsOptions}. */
  omit?: readonly GrantsPart[];
}

/**
 * Checks a catalog and returns the engine bound to it: the same functions as `unauth/z` exports,
 * with the catalog already given.
 *
 * @throws `ERR_AUTHZ_CATALOG_INVALID` as {@link defineCatalog} does.
 *
 * @example
 * export const authz = defineAuthz({
 *   permissions: ["report:read", "report:write", "access:manage"],
 *   presets: { viewer: ["report:read"], owner: ["*"] },
 * });
 *
 * const { allowed, diverged } = authz.could(session.data.grants, { permission: "report:write" });
 * if (!allowed) throw forbidden();
 */
export function defineAuthz<const TPermission extends string, const TPreset extends string = never>(
  data: CatalogData<TPermission, TPreset>,
  defaults?: AuthzOptions,
): Authz<TPermission, TPreset> {
  const catalog = defineCatalog(data);
  const omit = defaults?.omit;
  return {
    catalog,
    ask: (read, question, options) => ask(catalog, read, question, options),
    could: (grants, question, options) => could(catalog, grants, question, options),
    diverged: (grants, options) => diverged(catalog, grants, options),
    issueGrants: (read, options) =>
      issueGrants(catalog, read, { ...options, omit: options?.omit ?? omit }),
    validateStatement: (value, options) => validateStatement(catalog, value, options),
    validateRole: (value, options) => validateRole(catalog, value, options),
    resolveRole: (name, options) => resolveRole(catalog, name, options),
    relatedValues: (permission) => relatedValues(catalog, permission),
    placeFits: (key) => placeFits(catalog, key),
  };
}
