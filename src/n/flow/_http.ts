import type { ExpiresIn } from "unjwt/session";
import { computeDurationInSeconds } from "unjwt/utils";
import { safeJsonParse } from "unsecure/sanitize";
import { UnauthError, type UnauthErrorCauseMap } from "../../_internal/error.ts";
import { PROVIDER_DOCUMENT_MAX_BYTES, readText } from "./_http-body.ts";

/** The longest endpoint URL accepted; it also bounds the cache keys built from one. */
export const MAX_URL_LENGTH: number = 2048;

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

/** A `fetch` the caller injects; the global one otherwise. */
export type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/** The injected `fetch`, else the global one called unbound. */
export function fetchOf(options: { fetch?: Fetch } | undefined): Fetch {
  return options?.fetch ?? ((input, init) => globalThis.fetch(input, init));
}

/** The injected clock in ms, else `Date.now`. */
export function nowOf(options: { now?: () => number } | undefined): () => number {
  return options?.now ?? Date.now;
}

/** What {@link readObject} found: the object (`undefined` when the body is neither), or the cap it exceeded. */
export type ObjectBody = { object: Record<string, unknown> | undefined } | { tooLarge: number };

/**
 * A JSON or form-encoded object body, without prototype-polluting keys; a body longer than
 * {@link PROVIDER_DOCUMENT_MAX_BYTES} is reported as `tooLarge`, unread.
 */
export async function readObject(
  response: Response,
  options: { signal?: AbortSignal } = {},
): Promise<ObjectBody> {
  const maxBytes = PROVIDER_DOCUMENT_MAX_BYTES;
  const text = await readText(response, { maxBytes, signal: options.signal }).catch(() => "");
  if (text === undefined) return { tooLarge: maxBytes };
  const type = response.headers.get("content-type") ?? "";
  if (type.includes("application/x-www-form-urlencoded"))
    return { object: formObject(new URLSearchParams(text)) };
  try {
    const parsed: unknown = safeJsonParse(text);
    return { object: isRecord(parsed) ? parsed : undefined };
  } catch {
    return { object: undefined };
  }
}

/** Form fields as an object with no prototype. */
export function formObject(form: URLSearchParams): Record<string, string> {
  const object: Record<string, string> = Object.create(null);
  for (const [name, value] of form) {
    if (name !== "__proto__") object[name] = value;
  }
  return object;
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

/**
 * Refuses an endpoint that is not `https:` or longer than {@link MAX_URL_LENGTH}; plain `http:`
 * passes on a loopback host, for a provider running next to the app in development, or on a host
 * `insecureHosts` lists.
 */
export function assertSecureUrl(
  value: string,
  options: { label: string; insecureHosts?: string[] },
): URL {
  if (value.length > MAX_URL_LENGTH) {
    throw configError(
      `${options.label} must be at most ${MAX_URL_LENGTH} characters, got ${value.length}.`,
    );
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw configError(
      `${options.label} must be an absolute URL, got ${JSON.stringify(value)}.`,
      error,
    );
  }
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:" && insecureHost(url.hostname, options.insecureHosts)) return url;
  throw configError(
    `${options.label} must use https: (or http: on localhost or a host in "insecureHosts"), got ${JSON.stringify(value)}.`,
  );
}

/** `value` in seconds when it is a positive duration (`30`, `"10m"`), else `ERR_UNAUTH_CONFIG_INVALID`. */
export function durationSeconds(value: ExpiresIn, options: { label: string }): number {
  let seconds: number;
  try {
    seconds = computeDurationInSeconds(value);
  } catch (error) {
    throw durationError(value, options, error);
  }
  if (!Number.isFinite(seconds) || seconds <= 0) throw durationError(value, options);
  return seconds;
}

/** `ERR_UNAUTH_CONFIG_INVALID` (500) with the `[unauth/n]` prefix. */
export function configError(
  message: string,
  cause?: unknown,
): UnauthError<"ERR_UNAUTH_CONFIG_INVALID"> {
  return new UnauthError(`[unauth/n] ${message}`, "ERR_UNAUTH_CONFIG_INVALID", {
    status: 500,
    cause,
  });
}

/** The declared `cause` of `ERR_AUTHN_PROVIDER_ERROR`. */
export type ProviderFailure = UnauthErrorCauseMap["ERR_AUTHN_PROVIDER_ERROR"];

/** `ERR_AUTHN_PROVIDER_ERROR` (502): a provider endpoint gave no usable answer, `cause` saying why. */
export function providerError(
  message: string,
  cause: ProviderFailure,
): UnauthError<"ERR_AUTHN_PROVIDER_ERROR"> {
  return new UnauthError(`[unauth/n] ${message}`, "ERR_AUTHN_PROVIDER_ERROR", {
    status: 502,
    cause,
  });
}

/** `ERR_AUTHN_PROFILE_INVALID` (401): the account data names no usable identity. */
export function profileError(
  message: string,
  cause?: unknown,
): UnauthError<"ERR_AUTHN_PROFILE_INVALID"> {
  return new UnauthError(`[unauth/n] ${message}`, "ERR_AUTHN_PROFILE_INVALID", {
    status: 401,
    cause,
  });
}

function insecureHost(hostname: string, insecureHosts: string[] | undefined): boolean {
  if (LOOPBACK.has(hostname)) return true;
  return insecureHosts?.some((host) => host.toLowerCase() === hostname) ?? false;
}

function durationError(
  value: ExpiresIn,
  options: { label: string },
  cause?: unknown,
): UnauthError<"ERR_UNAUTH_CONFIG_INVALID"> {
  return configError(
    `${options.label} needs a positive "maxAge", got ${JSON.stringify(value)}.`,
    cause,
  );
}
