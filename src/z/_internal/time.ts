import { nowOf } from "../../_internal/shared.ts";
import { malformed } from "./errors.ts";

/** The last second of the year 9999: the largest time the model reads. */
export const MAX_TIME = 253402300799;

/** Whether `value` is a time: an integer count of seconds from 0 to {@link MAX_TIME}. */
export function isTime(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= MAX_TIME;
}

/**
 * `value` when it is a time, else `ERR_AUTHZ_MALFORMED`: a count of milliseconds, a fraction or a
 * negative number never passes for one.
 */
export function assertTime(value: unknown): number {
  if (!isTime(value))
    throw malformed("The time is not a count of seconds.", { what: "time", value });
  return value;
}

/**
 * The time of one call: the clock read once, in whole seconds. A clock that reads before the
 * epoch, past {@link MAX_TIME} or not a number is `ERR_AUTHZ_MALFORMED`.
 */
export function clockSeconds(options?: { now?: () => number }): number {
  return assertTime(Math.floor(nowOf(options)() / 1000));
}

/** Whether something that ends at `expiresAt`, or never when absent, is still live at second `t`. */
export function isLive(expiresAt: number | undefined, t: number): boolean {
  return expiresAt === undefined || expiresAt > t;
}
