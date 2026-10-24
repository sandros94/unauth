import { safeJsonParse } from "unsecure/sanitize";
import { type Fetch, endpointName, isRecord, providerError } from "./shared.ts";
import {
  PROVIDER_DOCUMENT_MAX_BYTES,
  PROVIDER_FETCH_TIMEOUT,
  discardBody,
  isAbort,
  raced,
  readText,
} from "./body.ts";

/** Options of {@link getJson} and {@link getObject}. */
export interface GetJsonOptions {
  fetch: Fetch;
  headers?: Record<string, string>;
  /** Names the endpoint in error messages. */
  label: string;
  /** Deadline in ms for the request and its body together. */
  timeout?: number;
  /** The most bytes the body may have. */
  maxBytes?: number;
}

/**
 * GETs JSON from a provider endpoint, refusing redirects, bodies over `maxBytes` and answers
 * slower than `timeout`; any failure is `ERR_AUTHN_PROVIDER_ERROR`, its `cause.reason` saying which.
 * Messages name the endpoint without its query, which may carry a credential.
 */
export async function getJson(url: string, options: GetJsonOptions): Promise<unknown> {
  const { label, timeout = PROVIDER_FETCH_TIMEOUT } = options;
  const maxBytes = options.maxBytes ?? PROVIDER_DOCUMENT_MAX_BYTES;
  const at = endpointName(label, url);
  const signal = AbortSignal.timeout(timeout);
  const deadline = (cause: unknown, status?: number) =>
    providerError(`The ${at} did not answer within ${timeout} ms.`, {
      reason: "timeout",
      status,
      cause,
    });

  let response: Response;
  try {
    const headers = { accept: "application/json", ...options.headers };
    response = await raced(options.fetch(url, { headers, signal, redirect: "error" }), signal);
  } catch (error) {
    if (isAbort(error)) throw deadline(error);
    throw providerError(`Could not reach the ${at}.`, { reason: "unreachable", cause: error });
  }
  if (!response.ok) {
    discardBody(response);
    throw providerError(`The ${at} answered ${response.status}.`, {
      reason: "status",
      status: response.status,
    });
  }

  try {
    const text = await raced(readText(response, { maxBytes, signal, fatal: true }), signal);
    if (text !== undefined) return safeJsonParse(text);
  } catch (error) {
    if (isAbort(error)) throw deadline(error, response.status);
    throw providerError(`The ${at} did not answer JSON.`, {
      reason: "malformed",
      status: response.status,
      cause: error,
    });
  }
  throw providerError(`The ${at} answered more than the ${maxBytes} bytes allowed.`, {
    reason: "too-large",
    status: response.status,
  });
}

/** GETs a JSON object from a provider endpoint; anything else is `ERR_AUTHN_PROVIDER_ERROR`. */
export async function getObject(
  url: string,
  options: GetJsonOptions,
): Promise<Record<string, unknown>> {
  const body = await getJson(url, options);
  if (!isRecord(body)) {
    throw providerError(`The ${endpointName(options.label, url)} did not answer a JSON object.`, {
      reason: "malformed",
    });
  }
  return body;
}
