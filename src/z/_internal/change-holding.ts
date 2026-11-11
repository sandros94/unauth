import type { Author } from "./change-input.ts";
import { type DecisionSource, blocks, decidePermission } from "./decide.ts";
import { covers } from "./keys.ts";
import { isPermanentManager } from "./statements.ts";
import { isLive } from "./time.ts";

/** What a change is checked against: the statements as they stand, its author, its time. */
export interface AuthorView {
  readonly source: DecisionSource;
  readonly author: Author;
  readonly time: number;
}

/** Whether the author manages `place` at the time of the change: false when the catalog names no manager. */
export function manages(view: AuthorView, place: string): boolean {
  const manager = view.source.catalog.manager;
  return manager !== undefined && holds(view, [manager], place);
}

/** Whether the author holds every one of `permissions` at `place` at the time of the change. */
export function holds(view: AuthorView, permissions: Iterable<string>, place: string): boolean {
  return holdsAt(view, permissions, place, view.time);
}

/**
 * Whether the author holds every one of `permissions` at `place` from the time of the change until
 * `end`, for ever when `end` is absent. A holding stops only where a statement ends, so it is
 * asked at the time of the change and again at each end, later than that time and earlier than
 * `end`, of a statement about one of the author's identifiers at a place covering `place`.
 */
export function holdsUntil(
  view: AuthorView,
  permissions: Iterable<string>,
  place: string,
  end: number | undefined,
): boolean {
  for (const time of instants(view, place, end)) {
    if (!holdsAt(view, permissions, place, time)) return false;
  }
  return true;
}

/**
 * Whether a deny live at the time of the change, about the author or one of its groups, at a place
 * strictly under `place`, blocks one of `permissions`. Never for a permanent manager.
 */
export function deniedUnder(
  view: AuthorView,
  permissions: Iterable<string>,
  place: string,
): boolean {
  const { source, author, time } = view;
  if (isPermanentManager(source.statements, author)) return false;
  const identifiers = identifiersOf(author);
  const asked = [...permissions];
  return source.statements.some(
    (statement) =>
      statement.kind === "deny" &&
      identifiers.has(statement.subject) &&
      statement.place !== place &&
      covers(place, statement.place) &&
      isLive(statement.expiresAt, time) &&
      asked.some((permission) => blocks(source.catalog, statement, permission)),
  );
}

/** Whether the author is a permanent manager. */
export function isPermanent(view: AuthorView): boolean {
  return isPermanentManager(view.source.statements, view.author);
}

function holdsAt(
  view: AuthorView,
  permissions: Iterable<string>,
  place: string,
  time: number,
): boolean {
  const { subject, groups } = view.author;
  for (const permission of permissions) {
    const asked = { subject, groups, place, time, permission };
    if (!decidePermission(view.source, asked).allowed) return false;
  }
  return true;
}

function instants(view: AuthorView, place: string, end: number | undefined): Set<number> {
  const { source, author, time } = view;
  const identifiers = identifiersOf(author);
  const out = new Set([time]);
  for (const statement of source.statements) {
    const ends = statement.expiresAt;
    if (ends === undefined || ends <= time || (end !== undefined && ends >= end)) continue;
    if (identifiers.has(statement.subject) && covers(statement.place, place)) out.add(ends);
  }
  return out;
}

function identifiersOf(author: Author): Set<string> {
  return new Set([author.subject, ...author.groups]);
}
