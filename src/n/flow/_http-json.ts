import { safeJsonParse } from "unsecure";
import { type Fetch, isRecord, providerError } from "./_http.ts";
import {
  PROVIDER_DOCUMENT_MAX_BYTES,
  PROVIDER_FETCH_TIMEOUT,
  discardBody,
  isAbort,
  raced,
  readText,
} from "./_http-body.ts";

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
 * slower than `timeout`; any failure is `ERR_AUTHN_PROVIDER_ERROR`.
 */
export async function getJson(url: string, options: GetJsonOptions): Promise<unknown> {
  const { label, timeout = PROVIDER_FETCH_TIMEOUT } = options;
  const maxBytes = options.maxBytes ?? PROVIDER_DOCUMENT_MAX_BYTES;
  const signal = AbortSignal.timeout(timeout);
  const failure = (message: string, cause: unknown) =>
    providerError(
      isAbort(cause) ? `The ${label} at ${url} did not answer within ${timeout} ms.` : message,
      cause,
    );
  let response: Response;
  try {
    const headers = { accept: "application/json", ...options.headers };
    response = await raced(options.fetch(url, { headers, signal, redirect: "error" }), signal);
  } catch (error) {
    throw failure(`Could not reach the ${label} at ${url}.`, error);
  }
  if (!response.ok) {
    discardBody(response);
    throw providerError(`The ${label} at ${url} answered ${response.status}.`, {
      status: response.status,
    });
  }
  try {
    const text = await raced(readText(response, { maxBytes, signal, fatal: true }), signal);
    if (text !== undefined) return safeJsonParse(text);
  } catch (error) {
    throw failure(`The ${label} at ${url} did not answer JSON.`, error);
  }
  throw providerError(`The ${label} at ${url} answered more than the ${maxBytes} bytes allowed.`);
}

/** GETs a JSON object from a provider endpoint; anything else is `ERR_AUTHN_PROVIDER_ERROR`. */
export async function getObject(
  url: string,
  options: GetJsonOptions,
): Promise<Record<string, unknown>> {
  const body = await getJson(url, options);
  if (!isRecord(body))
    throw providerError(`The ${options.label} at ${url} did not answer a JSON object.`);
  return body;
}
