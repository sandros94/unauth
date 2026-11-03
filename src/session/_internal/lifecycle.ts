import type { OpaqueSessionRecord, OpaqueSessionTimes } from "../opaque-store.ts";

/** The lifetimes a definition decided, in ms; `undefined` is none. */
export interface Lifetimes {
  /** Absolute: the session ends this long after it was created, whatever happens. */
  maxAge: number | undefined;
  /** Idle: the session ends this long after its last activity. */
  idle: number | undefined;
}

/** When a session created at `createdAt` and active at `now` ends; `undefined` for never. */
export function endOf(
  lifetimes: Lifetimes,
  at: { createdAt: number; now: number },
): number | undefined {
  const absolute = lifetimes.maxAge === undefined ? undefined : at.createdAt + lifetimes.maxAge;
  const idle = lifetimes.idle === undefined ? undefined : at.now + lifetimes.idle;
  if (absolute === undefined) return idle;
  if (idle === undefined) return absolute;
  return Math.min(absolute, idle);
}

/** The absolute end alone, what the cookie's `Expires` carries; `undefined` is a browser-session cookie. */
export function absoluteEndOf(lifetimes: Lifetimes, createdAt: number): number | undefined {
  return lifetimes.maxAge === undefined ? undefined : createdAt + lifetimes.maxAge;
}

/** Whether `record` has ended by `now`. */
export function hasEnded(record: OpaqueSessionRecord<unknown>, now: number): boolean {
  return record.expiresAt !== undefined && record.expiresAt <= now;
}

/**
 * Whether a read at `now` extends `record`: an idle lifetime is set, and at least half of it has
 * passed since the last activity, so a busy session costs one write per half-idle, not per read.
 */
export function isDueForTouch(
  record: OpaqueSessionRecord<unknown>,
  lifetimes: Lifetimes,
  now: number,
): boolean {
  return lifetimes.idle !== undefined && now - record.updatedAt >= lifetimes.idle / 2;
}

/** The times a write at `now` gives `record`. */
export function timesAt(
  record: Pick<OpaqueSessionRecord<unknown>, "createdAt">,
  lifetimes: Lifetimes,
  now: number,
): OpaqueSessionTimes {
  return { updatedAt: now, expiresAt: endOf(lifetimes, { createdAt: record.createdAt, now }) };
}
