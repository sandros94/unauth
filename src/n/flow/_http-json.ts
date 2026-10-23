import { safeJsonParse } from "unsecure/sanitize";
import { type Fetch, isRecord, providerError, readObject } from "./_http.ts";
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
 * slower than `timeout`; any failure is `ERR_AUTHN_PROVIDER_ERROR`, its `cause.reason` saying which.
 */
export async function getJson(url: string, options: GetJsonOptions): Promise<unknown> {
  const { label, timeout = PROVIDER_FETCH_TIMEOUT } = options;
  const maxBytes = options.maxBytes ?? PROVIDER_DOCUMENT_MAX_BYTES;
  const signal = AbortSignal.timeout(timeout);
  const deadline = (cause: unknown, status?: number) =>
    providerError(`The ${label} at ${url} did not answer within ${timeout} ms.`, {
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
    throw providerError(`Could not reach the ${label} at ${url}.`, {
      reason: "unreachable",
      cause: error,
    });
  }
  if (!response.ok) {
    discardBody(response);
    throw providerError(`The ${label} at ${url} answered ${response.status}.`, {
      reason: "status",
      status: response.status,
    });
  }

  try {
    const text = await raced(readText(response, { maxBytes, signal, fatal: true }), signal);
    if (text !== undefined) return safeJsonParse(text);
  } catch (error) {
    if (isAbort(error)) throw deadline(error, response.status);
    throw providerError(`The ${label} at ${url} did not answer JSON.`, {
      reason: "malformed",
      status: response.status,
      cause: error,
    });
  }
  throw providerError(`The ${label} at ${url} answered more than the ${maxBytes} bytes allowed.`, {
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
    throw providerError(`The ${options.label} at ${url} did not answer a JSON object.`, {
      reason: "malformed",
    });
  }
  return body;
}

/** Options of {@link postForm}. */
export interface PostFormOptions extends Omit<GetJsonOptions, "headers"> {
  /** Extra headers; `accept` and `content-type` are the form POST's own. */
  headers?: HeadersInit;
}

/** What a form POST answered, whatever its status; `body` is `undefined` when it was not an object. */
export interface FormAnswer {
  ok: boolean;
  status: number;
  headers: Headers;
  body: Record<string, unknown> | undefined;
}

/**
 * POSTs a form to a provider endpoint and reads its JSON or form-encoded object body, refusing
 * redirects, bodies over `maxBytes` and answers slower than `timeout`. The status is the caller's
 * to read: only no usable answer at all throws, as `ERR_AUTHN_PROVIDER_ERROR` with the
 * `cause.reason` saying why.
 */
export async function postForm(
  url: string,
  form: URLSearchParams,
  options: PostFormOptions,
): Promise<FormAnswer> {
  const { label, timeout = PROVIDER_FETCH_TIMEOUT } = options;
  const signal = AbortSignal.timeout(timeout);
  const deadline = (cause: unknown, status?: number) =>
    providerError(`The ${label} at ${url} did not answer within ${timeout} ms.`, {
      reason: "timeout",
      status,
      cause,
    });
  const headers = new Headers(options.headers);
  headers.set("accept", "application/json");
  headers.set("content-type", "application/x-www-form-urlencoded");

  let response: Response;
  try {
    response = await raced(
      options.fetch(url, { method: "POST", headers, body: form, signal, redirect: "error" }),
      signal,
    );
  } catch (error) {
    if (isAbort(error)) throw deadline(error);
    throw providerError(`Could not reach the ${label} at ${url}.`, {
      reason: "unreachable",
      cause: error,
    });
  }

  let answer: Awaited<ReturnType<typeof readObject>>;
  try {
    answer = await raced(readObject(response, { signal }), signal);
  } catch (error) {
    throw deadline(error, response.status);
  }

  if ("tooLarge" in answer) {
    throw providerError(
      `The ${label} at ${url} answered more than the ${answer.tooLarge} bytes allowed.`,
      { reason: "too-large", status: response.status },
    );
  }

  return {
    ok: response.ok,
    status: response.status,
    headers: response.headers,
    body: answer.object,
  };
}
