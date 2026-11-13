import type { CompiledCatalog } from "./compiled.ts";
import { chainOf } from "./keys.ts";
import { blocking, expand, removed, wanted } from "./permissions.ts";
import type { RoleReader } from "./roles.ts";
import type { ReadStatement } from "./statements.ts";
import { isLive } from "./time.ts";

/** What every decision reads: the catalog, the stored roles and the statements, read once. */
export interface DecisionSource {
  readonly catalog: CompiledCatalog;
  readonly roles: RoleReader;
  readonly statements: readonly ReadStatement[];
}

/**
 * Who asks, where and when. `subject` tells the statements about the asker itself from those about
 * its groups, `place` is a canonical key that fits the catalog, `time` a time in seconds.
 */
export interface Asked {
  readonly subject: string;
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
 * Decides one declared, concrete permission from the statements, as the model's `decide`: a live
 * deny on the chain that blocks it denies, whatever else its subject holds; else what allows and
 * assignments give, walked from the root down with exclusions taken out at each place, allows when
 * the permission or one implying it is left. Every statement applies: one about `subject` is the
 * asker's own, any other a group's. Statements off the chain or ended at `time` are skipped. An
 * inert statement needs no filter: one on the chain of a place that fits fits too, and one that
 * names nothing declared gives, removes and blocks nothing.
 */
export function decidePermission(
  source: DecisionSource,
  asked: Asked & { readonly permission: string },
): Ruling {
  const { permission } = asked;
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

/** The statements live at `time` on the chain of `place`. */
function relevantTo(statements: readonly ReadStatement[], asked: Asked): ReadStatement[] {
  const chain = new Set(chainOf(asked.place));
  return statements.filter(
    (statement) => chain.has(statement.place) && isLive(statement.expiresAt, asked.time),
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
          : roles.resolve(statement.value).gives;
      for (const permission of satisfiedBy(given, satisfying)) {
        let held = carried.get(statement.subject);
        if (!held) carried.set(statement.subject, (held = new Map()));
        const first = held.get(permission);
        if (!first || (first.kind === "assign" && statement.kind === "allow")) {
          held.set(permission, statement);
        }
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
  const own = carried.get(asked.subject);
  for (const held of own ? [own, ...carried.values()] : carried.values()) {
    const giving = [...held.values()];
    const named = giving.find((statement) => statement.kind === "allow") ?? giving[0];
    if (named) return named;
  }
  return undefined;
}

/** The permissions of `given` that are in `satisfying`, in the order of `given`. */
function satisfiedBy(given: ReadonlySet<string>, satisfying: ReadonlySet<string>): string[] {
  const found = [...satisfying].filter((permission) => given.has(permission));
  if (found.length < 2) return found;
  return [...given].filter((permission) => satisfying.has(permission));
}
