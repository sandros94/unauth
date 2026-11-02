import type { ExpiresIn } from "unjwt/session";
import { computeDurationInSeconds } from "unjwt/utils";
import { UnauthError } from "../error.ts";

/** The injected clock in ms, else `Date.now`. */
export function nowOf(options: { now?: () => number } | undefined): () => number {
  return options?.now ?? Date.now;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function stringField(
  object: Record<string, unknown> | undefined,
  name: string,
): string | undefined {
  const value = object?.[name];
  return typeof value === "string" && value !== "" ? value : undefined;
}

/** `value` in seconds when it is a positive duration (`30`, `"10m"`), else `ERR_UNAUTH_CONFIG_INVALID`. */
export function durationSeconds(
  value: ExpiresIn,
  options: { label: string; prefix: string },
): number {
  let seconds: number;
  try {
    seconds = computeDurationInSeconds(value);
  } catch (error) {
    throw durationError(value, options, error);
  }
  if (!Number.isFinite(seconds) || seconds <= 0) throw durationError(value, options);
  return seconds;
}

/** `ERR_UNAUTH_CONFIG_INVALID` (500), its message starting with `prefix`. */
export function configError(
  message: string,
  options: { prefix: string; cause?: unknown },
): UnauthError<"ERR_UNAUTH_CONFIG_INVALID"> {
  return new UnauthError(`${options.prefix} ${message}`, "ERR_UNAUTH_CONFIG_INVALID", {
    status: 500,
    cause: options.cause,
  });
}

function durationError(
  value: ExpiresIn,
  options: { label: string; prefix: string },
  cause?: unknown,
): UnauthError<"ERR_UNAUTH_CONFIG_INVALID"> {
  return configError(`${options.label} needs a positive "maxAge", got ${JSON.stringify(value)}.`, {
    prefix: options.prefix,
    cause,
  });
}
