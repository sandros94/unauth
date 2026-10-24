import type { GetJsonOptions } from "./json.ts";
import { endpointName, providerError, readObject } from "./shared.ts";
import {
  PROVIDER_DOCUMENT_MAX_BYTES,
  PROVIDER_FETCH_TIMEOUT,
  isAbort,
  raced,
  readText,
} from "./body.ts";

/** Options of {@link postForm} and {@link postText}. */
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

/** What a form POST answered as text, whatever its status. */
export interface TextAnswer {
  ok: boolean;
  status: number;
  headers: Headers;
  text: string;
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
  const sent = await sendForm(url, form, options, "application/json");
  const { response, signal, deadline } = sent;

  let answer: Awaited<ReturnType<typeof readObject>>;
  try {
    answer = await raced(readObject(response, { signal }), signal);
  } catch (error) {
    throw deadline(error, response.status);
  }
  if ("tooLarge" in answer) throw sent.tooLarge(answer.tooLarge);

  return {
    ok: response.ok,
    status: response.status,
    headers: response.headers,
    body: answer.object,
  };
}

/**
 * POSTs a form to a provider endpoint and reads its body as UTF-8 text, with {@link postForm}'s
 * limits and failures; malformed bytes are `ERR_AUTHN_PROVIDER_ERROR` too. The status is the
 * caller's to read.
 */
export async function postText(
  url: string,
  form: URLSearchParams,
  options: PostFormOptions,
): Promise<TextAnswer> {
  const sent = await sendForm(url, form, options, "text/plain");
  const { response, signal, deadline } = sent;
  const maxBytes = options.maxBytes ?? PROVIDER_DOCUMENT_MAX_BYTES;

  let text: string | undefined;
  try {
    text = await raced(readText(response, { maxBytes, signal, fatal: true }), signal);
  } catch (error) {
    if (isAbort(error)) throw deadline(error, response.status);
    throw providerError(`The ${sent.at} did not answer text.`, {
      reason: "malformed",
      status: response.status,
      cause: error,
    });
  }
  if (text === undefined) throw sent.tooLarge(maxBytes);

  return { ok: response.ok, status: response.status, headers: response.headers, text };
}

/** The request half of a form POST: the response, or the unreachable/timeout failure. */
async function sendForm(
  url: string,
  form: URLSearchParams,
  options: PostFormOptions,
  accept: string,
): Promise<{
  response: Response;
  signal: AbortSignal;
  at: string;
  deadline: (cause: unknown, status?: number) => Error;
  tooLarge: (maxBytes: number) => Error;
}> {
  const { label, timeout = PROVIDER_FETCH_TIMEOUT } = options;
  const at = endpointName(label, url);
  const signal = AbortSignal.timeout(timeout);
  const deadline = (cause: unknown, status?: number) =>
    providerError(`The ${at} did not answer within ${timeout} ms.`, {
      reason: "timeout",
      status,
      cause,
    });
  const headers = new Headers(options.headers);
  headers.set("accept", accept);
  headers.set("content-type", "application/x-www-form-urlencoded");

  let response: Response;
  try {
    response = await raced(
      options.fetch(url, { method: "POST", headers, body: form, signal, redirect: "error" }),
      signal,
    );
  } catch (error) {
    if (isAbort(error)) throw deadline(error);
    throw providerError(`Could not reach the ${at}.`, { reason: "unreachable", cause: error });
  }
  const tooLarge = (maxBytes: number) =>
    providerError(`The ${at} answered more than the ${maxBytes} bytes allowed.`, {
      reason: "too-large",
      status: response.status,
    });
  return { response, signal, at, deadline, tooLarge };
}
