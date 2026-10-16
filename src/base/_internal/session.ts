import type { ExpiresIn } from "unjwt";
import { computeDurationInSeconds } from "unjwt/utils";
import { DEFAULT_ROLLING_WINDOW } from "./defaults.ts";

/**
 * `rolling` as unauth accepts it: unjwt's `true | ExpiresIn`, plus `false` to disable,
 * and `undefined` for the default window of {@link DEFAULT_ROLLING_WINDOW} × `maxAge`.
 */
export type RollingOption = boolean | ExpiresIn;

/** Resolves unauth's `rolling` option into the value unjwt's session config takes. */
export function resolveRolling(
  rolling: RollingOption | undefined,
  maxAge: ExpiresIn,
): true | ExpiresIn | undefined {
  if (rolling === false) return undefined;
  if (rolling === undefined) {
    return Math.max(1, Math.floor(computeDurationInSeconds(maxAge) * DEFAULT_ROLLING_WINDOW));
  }
  return rolling;
}
