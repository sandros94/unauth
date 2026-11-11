import { UnauthError } from "../error.ts";
import type { AuthorView } from "./_internal/change-holding.ts";
import { readAuthor, readChange } from "./_internal/change-input.ts";
import {
  assertGenesisStatement,
  readManagers,
  readManagersIfGiven,
} from "./_internal/change-root.ts";
import { type ChangeReason, genesisRefusals, refusalsOf } from "./_internal/change-rules.ts";
import { compiledOf } from "./_internal/compile.ts";
import { roleReader } from "./_internal/roles.ts";
import { readStatements } from "./_internal/statements.ts";
import { clockSeconds } from "./_internal/time.ts";
import type { Catalog } from "./catalog.ts";
import type { StatementsOptions } from "./decide.ts";
import type { Statement, StoredRole } from "./types.ts";

/** A change to what is stored: a statement placed or removed, or a stored role defined or edited. */
export type Change =
  | { action: "place" | "remove"; statement: Statement }
  | { action: "define"; role: StoredRole };

/** Options of {@link checkChange}. */
export interface CheckChangeOptions extends StatementsOptions {
  /** Who asks for the change. */
  author: string;
  /** Every group the author belongs to. */
  groups?: readonly string[];
  /**
   * The permanent allows of `*` at the root, read in the same transaction as the write. Only a
   * change that removes one or places an end over one needs them, for the rule that the root keeps
   * a permanent manager: without them that change is refused, since nothing proves another exists.
   * A root that holds none has none to lose. Never needed to place one, which only a permanent
   * manager does here: the first one is placed through {@link checkGenesis}.
   */
  managers?: readonly Statement[];
}

/** Options of {@link checkGenesis}. */
export interface CheckGenesisOptions {
  /**
   * The permanent allows of `*` at the root, read in the same transaction as the write. Required:
   * genesis is open only while there is none, and nothing but this read proves it.
   */
  managers: readonly Statement[];
  /** The clock, in ms. Read once per call. @default Date.now */
  now?: () => number;
}

/**
 * Checks that the author may make a change, against the statements and never against grants.
 * Returns when it may be written, throws when it may not. Run it and the write in one
 * transaction of the application's storage, so that two changes cannot both pass on what only one
 * of them leaves true.
 *
 * Needs every statement about the author and each of the author's groups. It never accepts the
 * first permanent manager of the root, whatever `managers` holds: a permanent allow of `*` at the
 * root is placed here only by a permanent manager, and genesis is {@link checkGenesis}.
 *
 * @throws `ERR_AUTHZ_CHANGE_REFUSED` when a rule refuses it, each reason in `cause.reasons`.
 * @throws `ERR_AUTHZ_ROLE_INVALID` for a role that is unknown where it is assigned, or defined with
 * a cycle, a reference it cannot make, or a name already taken along its place.
 * @throws `ERR_AUTHZ_PERMISSION_UNKNOWN`, `ERR_AUTHZ_PLACE_OUTSIDE` or `ERR_AUTHZ_MALFORMED` for a
 * statement or a role the catalog does not accept.
 *
 * @example
 * await db.transaction(async (tx) => {
 *   const statements = await tx.select().from(grantsTable).where(inArray(grantsTable.subject, [author, ...teams]));
 *   checkChange(catalog, { action: "place", statement }, { author, groups: teams, statements });
 *   await tx.insert(grantsTable).values(statement).onConflictDoUpdate(sameIdentity);
 * });
 */
export function checkChange(catalog: Catalog, change: Change, options: CheckChangeOptions): void {
  const compiled = compiledOf(catalog);
  const author = readAuthor(options);
  const roles = roleReader(compiled, options.roles);
  const read = readChange(compiled, change, { reader: roles, given: options.roles });
  const statements = readStatements(compiled, options.statements);
  const managers = readManagersIfGiven(compiled, options.managers);
  const view: AuthorView = {
    source: { catalog: compiled, roles, statements },
    author,
    time: clockSeconds(options),
  };
  const reasons = refusalsOf(view, read, managers);
  if (reasons.length > 0) throw changeRefused(reasons);
}

/**
 * Checks genesis: placing the first permanent manager, a permanent allow of `*` at the root,
 * while the root holds none. It takes no author: anyone may make this change, about anyone, the
 * one change made by someone who is not a manager. Returns when it may be written, throws when it
 * may not.
 *
 * Nothing here tells a bootstrap from a request. Call it only where the application bootstraps,
 * never on a path an ordinary request reaches, and in the transaction that writes the statement,
 * so that the root is still empty when the write lands.
 *
 * @throws `ERR_AUTHZ_CHANGE_REFUSED` with `not-manager` when the catalog designates no manager
 * permission, `not-first` when the root already holds a permanent manager.
 * @throws `ERR_AUTHZ_MALFORMED` (`statement`) for a statement that is not a permanent allow of `*`
 * at the root about a subject, and for `managers` that are not a list of statements.
 *
 * @example
 * await db.transaction(async (tx) => {
 *   const managers = await tx.select().from(grantsTable).where(rootManagements);
 *   checkGenesis(catalog, { kind: "allow", subject: "deploy", value: "*" }, { managers });
 *   await tx.insert(grantsTable).values({ kind: "allow", subject: "deploy", value: "*" });
 * });
 */
export function checkGenesis(
  catalog: Catalog,
  statement: Statement,
  options: CheckGenesisOptions,
): void {
  const compiled = compiledOf(catalog);
  assertGenesisStatement(statement);
  const managers = readManagers(compiled, options?.managers);
  clockSeconds(options);
  const reasons = genesisRefusals(compiled, managers);
  if (reasons.length > 0) throw changeRefused(reasons);
}

function changeRefused(reasons: ChangeReason[]): UnauthError<"ERR_AUTHZ_CHANGE_REFUSED"> {
  return new UnauthError("The change is not allowed.", "ERR_AUTHZ_CHANGE_REFUSED", {
    status: 403,
    cause: { reasons },
  });
}
