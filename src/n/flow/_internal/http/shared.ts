import type { ExpiresIn } from "unjwt/session";
import { safeJsonParse } from "unsecure/sanitize";
import { UnauthError, type UnauthErrorCauseMap } from "../../../../error.ts";
import {
  configError as prefixedConfigError,
  durationSeconds as prefixedDurationSeconds,
  isRecord,
} from "../../../../_internal/shared.ts";
import { PROVIDER_DOCUMENT_MAX_BYTES, readText } from "./body.ts";

/** The longest endpoint URL accepted; it also bounds the cache keys built from one. */
export const MAX_URL_LENGTH: number = 2048;

const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

const PREFIX = "[unauth/n]";

/** A `fetch` the caller injects; the global one otherwise. */
export type Fetch = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

/**
 * The injected `fetch`, else {@link globalFetch}: one function for every caller that injects none,
 * since the document caches keep their entries apart per `fetch`.
 */
export function fetchOf(options: { fetch?: Fetch } | undefined): Fetch {
  return options?.fetch ?? globalFetch;
}

/** The global `fetch`, looked up at each call (a test may stub it) and called unbound. */
const globalFetch: Fetch = (input, init) => globalThis.fetch(input, init);

/** What {@link readObject} found: the object (`undefined` when the body is neither), or the cap it exceeded. */
export type ObjectBody = { object: Record<string, unknown> | undefined } | { tooLarge: number };

/**
 * A JSON or form-encoded object body, without prototype-polluting keys; a body longer than
 * `maxBytes` ({@link PROVIDER_DOCUMENT_MAX_BYTES} by default) is reported as `tooLarge`, unread.
 */
export async function readObject(
  response: Response,
  options: { signal?: AbortSignal; maxBytes?: number } = {},
): Promise<ObjectBody> {
  const maxBytes = options.maxBytes ?? PROVIDER_DOCUMENT_MAX_BYTES;
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

/**
 * `value` as a URL; `ERR_UNAUTH_CONFIG_INVALID` unless it is an absolute `https:` URL of at most
 * {@link MAX_URL_LENGTH} characters. Plain `http:` passes on a loopback host or a host
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

/**
 * `value` as a server URL a remote party chose (a URL read from a DID document or a server's
 * metadata, or typed by a visitor), checked for shape only: at most {@link MAX_URL_LENGTH}
 * characters, `http:` or `https:`, no credentials. Anything else is `ERR_AUTHN_PROVIDER_ERROR`
 * (`malformed`). Whether the server may be reached is {@link assertRemoteUrl}'s question.
 */
export function remoteUrl(value: string, options: { label: string }): URL {
  if (value.length > MAX_URL_LENGTH) {
    throw providerError(`${options.label} must be at most ${MAX_URL_LENGTH} characters.`, {
      reason: "malformed",
    });
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch (error) {
    throw providerError(`${options.label} must be an http: or https: URL.`, {
      reason: "malformed",
      cause: error,
    });
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw providerError(`${options.label} must be an http: or https: URL.`, {
      reason: "malformed",
    });
  }
  if (url.username !== "" || url.password !== "") {
    throw providerError(`${options.label} must carry no credentials.`, { reason: "malformed" });
  }
  return url;
}

/**
 * {@link remoteUrl}, then the sign-in's policy: a server `isServerAllowed` refuses is
 * `ERR_AUTHN_PROVIDER_ERROR` (`refused`); what it throws propagates as it is. The loopback and
 * `insecureHosts` exceptions of {@link assertSecureUrl} are for URLs the application configured,
 * never for ones a remote party chose.
 */
export function assertRemoteUrl(
  value: string,
  options: { label: string; isServerAllowed: (url: URL) => boolean },
): URL {
  const url = remoteUrl(value, options);
  if (!options.isServerAllowed(url)) {
    throw providerError(`${options.label} is not a server this sign-in may reach.`, {
      reason: "refused",
    });
  }
  return url;
}

/** `value` in seconds when it is a positive duration (`30`, `"10m"`), else `ERR_UNAUTH_CONFIG_INVALID`. */
export function durationSeconds(value: ExpiresIn, options: { label: string }): number {
  return prefixedDurationSeconds(value, { label: options.label, prefix: PREFIX });
}

/** `ERR_UNAUTH_CONFIG_INVALID` (500) with the `[unauth/n]` prefix. */
export function configError(
  message: string,
  cause?: unknown,
): UnauthError<"ERR_UNAUTH_CONFIG_INVALID"> {
  return prefixedConfigError(message, { prefix: PREFIX, cause });
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

/** `<label> at <url>` for a message, the URL without its query and fragment. */
export function endpointName(label: string, url: string): string {
  try {
    const parsed = new URL(url);
    return `${label} at ${parsed.origin}${parsed.pathname}`;
  } catch {
    return label;
  }
}
