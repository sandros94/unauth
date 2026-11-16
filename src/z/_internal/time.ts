import { nowOf } from "../../_internal/shared.ts";
import type { UnauthError } from "../../error.ts";
import { malformed, optionInvalid } from "./errors.ts";

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
  if (!isTime(value)) throw timeMalformed(value);
  return value;
}

/** `ERR_AUTHZ_MALFORMED` (`time`) for a value that is not a time. */
export function timeMalformed(value: unknown): UnauthError<"ERR_AUTHZ_MALFORMED"> {
  return malformed("The time is not a count of seconds.", { what: "time", value });
}

/**
 * The time of one call: the clock read once, in whole seconds. A clock that reads before the
 * epoch, past {@link MAX_TIME} or not a number is `ERR_AUTHZ_MALFORMED`.
 */
export function clockSeconds(options?: { now?: () => number }): number {
  return assertTime(Math.floor(nowOf(options)() / 1000));
}

/**
 * The two times of one read of grants, from the clock read once and its clock tolerance `T` in
 * seconds: `latest`, the time plus `T`, refused when earlier than the time of issue, and
 * `earliest`, the time less `T`, at which items are live.
 *
 * @throws `ERR_UNAUTH_CONFIG_INVALID` for a tolerance that is not a non-negative whole number of
 * seconds, and `ERR_AUTHZ_MALFORMED` for a clock that does not read a time.
 */
export function readTimes(options?: { now?: () => number; clockTolerance?: number }): {
  latest: number;
  earliest: number;
} {
  const tolerance = toleranceSeconds(options?.clockTolerance);
  const time = clockSeconds(options);
  return { latest: time + tolerance, earliest: time - tolerance };
}

/** Whether something that ends at `expiresAt`, or never when absent, is still live at second `t`. */
export function isLive(expiresAt: number | undefined, t: number): boolean {
  return expiresAt === undefined || expiresAt > t;
}

function toleranceSeconds(value: unknown): number {
  if (value === undefined) return 0;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw optionInvalid("clockTolerance", "a non-negative whole number of seconds", value);
  }
  return value;
}
