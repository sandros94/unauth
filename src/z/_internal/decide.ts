import type { CompiledCatalog } from "./compiled.ts";
import { chainOf } from "./keys.ts";
import { blocking, expand, removed, wanted } from "./permissions.ts";
import type { RoleReader } from "./roles.ts";
import { type ReadStatement, permanentManagementOf } from "./statements.ts";
import { isLive } from "./time.ts";

/** What every decision reads: the catalog, the stored roles and the statements, read once. */
export interface DecisionSource {
  readonly catalog: CompiledCatalog;
  readonly roles: RoleReader;
  readonly statements: readonly ReadStatement[];
}

/**
 * Who asks, where and when. `place` is a canonical key that fits the catalog, `time` a time in
 * seconds. `groups` must be whole: a group left out is a deny missed.
 */
export interface Asked {
  readonly subject: string;
  readonly groups: readonly string[];
  readonly place: string;
  readonly time: number;
}

/** The answer for one permission: the statement that decided, absent when nothing gave it. */
export interface Ruling {
  readonly permission: string;
  readonly allowed: boolean;
  readonly by?: ReadStatement;
}

/**
 * Decides one declared, concrete permission from the statements, as the model's `decide`: a
 * permanent manager is allowed, named by its permanent management; else a live deny on the chain
 * that blocks it denies; else what allows and assignments give, walked from the root down with
 * exclusions taken out at each place, allows when the permission or one implying it is left.
 * Statements about other identifiers, off the chain or ended at `time` are skipped.
 */
export function decidePermission(
  source: DecisionSource,
  asked: Asked & { readonly permission: string },
): Ruling {
  const { permission } = asked;
  const manager = permanentManagementOf(source.statements, asked);
  if (manager) return { permission, allowed: true, by: manager };
  const relevant = relevantTo(source.statements, asked);
  const deny = denyIn(source.catalog, relevant, permission);
  if (deny) return { permission, allowed: false, by: deny };
  const by = givenBy(source, relevant, asked);
  return by ? { permission, allowed: true, by } : { permission, allowed: false };
}

/**
 * Whether `statement` is a deny that blocks `permission`: what its pattern expands to holds the
 * permission or one the permission implies. Says nothing of its subject, place or time.
 */
export function blocks(
  catalog: CompiledCatalog,
  statement: ReadStatement,
  permission: string,
): boolean {
  if (statement.kind !== "deny") return false;
  const reached = blocking(catalog, permission);
  for (const denied of expand(catalog, statement.value)) if (reached.has(denied)) return true;
  return false;
}

/** The statements live at `time`, about `subject` or one of `groups`, on the chain of `place`. */
function relevantTo(statements: readonly ReadStatement[], asked: Asked): ReadStatement[] {
  const identifiers = new Set([asked.subject, ...asked.groups]);
  const chain = new Set(chainOf(asked.place));
  return statements.filter(
    (statement) =>
      identifiers.has(statement.subject) &&
      chain.has(statement.place) &&
      isLive(statement.expiresAt, asked.time),
  );
}

function denyIn(
  catalog: CompiledCatalog,
  relevant: readonly ReadStatement[],
  permission: string,
): ReadStatement | undefined {
  return relevant.find((statement) => blocks(catalog, statement, permission));
}

function givenBy(
  source: DecisionSource,
  relevant: readonly ReadStatement[],
  asked: Asked & { readonly permission: string },
): ReadStatement | undefined {
  const { catalog, roles } = source;
  const satisfying = wanted(catalog, asked.permission);
  const carried = new Map<string, Map<string, ReadStatement>>();
  for (const place of chainOf(asked.place).toReversed()) {
    const here = relevant.filter((statement) => statement.place === place);
    for (const statement of here) {
      if (statement.kind !== "allow" && statement.kind !== "assign") continue;
      const given =
        statement.kind === "allow"
          ? expand(catalog, statement.value)
          : roles.resolve(statement.value, place).gives;
      for (const permission of given) {
        if (!satisfying.has(permission)) continue;
        let held = carried.get(statement.subject);
        if (!held) carried.set(statement.subject, (held = new Map()));
        if (!held.has(permission)) held.set(permission, statement);
      }
    }
    for (const statement of here) {
      if (statement.kind !== "exclude") continue;
      const taken = removed(catalog, statement.value);
      const about =
        statement.subject === asked.subject ? carried.values() : [carried.get(statement.subject)];
      for (const held of about) if (held) for (const permission of taken) held.delete(permission);
    }
  }
  for (const identifier of [asked.subject, ...asked.groups]) {
    const held = carried.get(identifier);
    if (held) for (const statement of held.values()) return statement;
  }
  return undefined;
}
