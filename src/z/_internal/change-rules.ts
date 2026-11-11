import type { UnauthErrorCauseMap } from "../../error.ts";
import {
  type AuthorView,
  deniedUnder,
  holds,
  holdsUntil,
  isPermanent,
  manages,
} from "./change-holding.ts";
import type { ReadChange } from "./change-input.ts";
import type { CompiledCatalog } from "./compiled.ts";
import { endsManagement, isRootIdentity, leavesRootEmpty } from "./change-root.ts";
import { expand } from "./permissions.ts";
import { type ReadStatement, isPermanentManagement } from "./statements.ts";

/** Why a change is refused. */
export type ChangeReason = UnauthErrorCauseMap["ERR_AUTHZ_CHANGE_REFUSED"]["reasons"][number];

/**
 * Every reason the rules on authority refuse `change` for, each once, in the order of
 * {@link inOrder}. Empty when the change may be written. `managers` are the root's permanent
 * managements, `undefined` when they were not handed in.
 */
export function refusalsOf(
  view: AuthorView,
  change: ReadChange,
  managers: readonly ReadStatement[] | undefined,
): ChangeReason[] {
  const reasons =
    change.action === "place"
      ? placing(view, change.statement, managers)
      : change.action === "remove"
        ? removing(view, change.statement, { inert: change.inert, managers })
        : defining(view, change.home, change.gives);
  return inOrder(reasons);
}

/**
 * Every reason genesis is refused for, in the order of {@link inOrder}: `not-manager` when the
 * catalog designates no manager permission, `not-first` when the root holds a permanent
 * management. Empty when it may be written.
 */
export function genesisRefusals(
  catalog: CompiledCatalog,
  managers: readonly ReadStatement[],
): ChangeReason[] {
  const reasons = new Set<ChangeReason>();
  if (catalog.manager === undefined) reasons.add("not-manager");
  if (managers.length > 0) reasons.add("not-first");
  return inOrder(reasons);
}

/**
 * `reasons` in the one order every refusal names them: `not-manager`, `not-held`, `about-self`,
 * `last-manager`, `not-first`, `ended`.
 */
export function inOrder(reasons: ReadonlySet<ChangeReason>): ChangeReason[] {
  return ORDER.filter((reason) => reasons.has(reason));
}

const ORDER: readonly ChangeReason[] = [
  "not-manager",
  "not-held",
  "about-self",
  "last-manager",
  "not-first",
  "ended",
];

function placing(
  view: AuthorView,
  statement: ReadStatement,
  managers: readonly ReadStatement[] | undefined,
): Set<ChangeReason> {
  const reasons = new Set<ChangeReason>();
  if (!manages(view, statement.place)) reasons.add("not-manager");
  if (!handsOutHeld(view, statement)) reasons.add("not-held");
  if (endsManagement(statement, managers) && !isPermanent(view)) reasons.add("not-held");
  if (statement.subject === view.author.subject) reasons.add("about-self");
  if (leavesRootEmpty("place", statement, managers)) reasons.add("last-manager");
  if (statement.expiresAt !== undefined && statement.expiresAt <= view.time) reasons.add("ended");
  return reasons;
}

function removing(
  view: AuthorView,
  statement: ReadStatement,
  options: { inert: boolean; managers: readonly ReadStatement[] | undefined },
): Set<ChangeReason> {
  const reasons = new Set<ChangeReason>();
  const own = statement.subject === view.author.subject;
  const restricts = statement.kind === "deny" || statement.kind === "exclude";
  if (!own || restricts) {
    if (!manages(view, statement.place)) reasons.add("not-manager");
    if (!options.inert && !couldGive(view, statement)) reasons.add("not-held");
    if (own) reasons.add("about-self");
  }
  if (leavesRootEmpty("remove", statement, options.managers)) reasons.add("last-manager");
  return reasons;
}

function defining(view: AuthorView, home: string, gives: ReadonlySet<string>): Set<ChangeReason> {
  const reasons = new Set<ChangeReason>();
  if (!manages(view, home)) reasons.add("not-manager");
  if (!holdsUntil(view, gives, home, undefined) || deniedUnder(view, gives, home)) {
    reasons.add("not-held");
  }
  return reasons;
}

function handsOutHeld(view: AuthorView, statement: ReadStatement): boolean {
  const { catalog, roles } = view.source;
  const { kind, value, place, expiresAt } = statement;
  if (kind === "deny" || kind === "exclude") return holds(view, expand(catalog, value), place);
  if (isPermanentManagement(statement)) return isPermanent(view);
  if (kind === "assign") {
    const assigner = catalog.assigner.get(value);
    if (assigner !== undefined && holdsUntil(view, [assigner], place, expiresAt)) return true;
  }
  const given = kind === "allow" ? expand(catalog, value) : roles.resolve(value, place).gives;
  return holdsUntil(view, given, place, expiresAt) && !deniedUnder(view, given, place);
}

function couldGive(view: AuthorView, statement: ReadStatement): boolean {
  const { catalog, roles } = view.source;
  const { kind, value, place } = statement;
  if (kind !== "assign") {
    if (isRootIdentity(statement) && !isPermanent(view)) return false;
    return holds(view, expand(catalog, value), place);
  }
  const assigner = catalog.assigner.get(value);
  if (assigner !== undefined && holds(view, [assigner], place)) return true;
  return holds(view, roles.resolve(value, place).gives, place);
}
