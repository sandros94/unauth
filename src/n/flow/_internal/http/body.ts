/** The most bytes a provider document or token response may have. */
export const PROVIDER_DOCUMENT_MAX_BYTES: number = 262_144;

/** How long a provider document may take to arrive, request and body together, in ms. */
export const PROVIDER_FETCH_TIMEOUT: number = 10_000;

/**
 * The body's bytes, or `undefined` once it is longer than `maxBytes`: a `content-length` over
 * the cap refuses it unread, a stream over it is cancelled at the first chunk past the cap.
 * An aborting `signal` cancels the read.
 */
export async function readBytes(
  response: Response,
  options: { maxBytes: number; signal?: AbortSignal },
): Promise<Uint8Array | undefined> {
  const { maxBytes, signal } = options;
  const declared = Number(response.headers.get("content-length") ?? 0);
  if (declared > maxBytes) {
    discardBody(response);
    return undefined;
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const cancel = () => void reader.cancel(signal?.reason).catch(() => undefined);
  signal?.addEventListener("abort", cancel, { once: true });
  try {
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        cancel();
        return undefined;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return bytes;
  } finally {
    signal?.removeEventListener("abort", cancel);
  }
}

/**
 * The body as UTF-8 text (`fatal` refuses malformed bytes), or `undefined` past `maxBytes`; see
 * {@link readBytes}.
 */
export async function readText(
  response: Response,
  options: { maxBytes: number; signal?: AbortSignal; fatal?: boolean },
): Promise<string | undefined> {
  const bytes = await readBytes(response, options);
  return bytes && new TextDecoder("utf-8", { fatal: options.fatal }).decode(bytes);
}

/** Drops a body nobody will read, so its connection is released. */
export function discardBody(response: Response): void {
  if (response.body && !response.bodyUsed) void response.body.cancel().catch(() => undefined);
}

/**
 * `promise`, or a rejection with the signal's reason as soon as `signal` aborts: a `fetch` that
 * ignores its signal still releases its callers at the deadline, and its late result goes nowhere.
 */
export function raced<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason);
    if (signal.aborted) abort();
    else signal.addEventListener("abort", abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", abort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", abort);
        reject(error);
      },
    );
  });
}

/** Whether `error` is what an aborted or timed-out request rejects with. */
export function isAbort(error: unknown): boolean {
  if (typeof error !== "object" || error === null || !("name" in error)) return false;
  return error.name === "TimeoutError" || error.name === "AbortError";
}
