import { sanitizeObjectCopy } from "unsecure/sanitize";
import { hash } from "unsecure/hash";
import { isRecord } from "./_http.ts";

/** How far in the future a driver entry's `loadedAt` may lie, for clocks drifting between instances. */
export const FUTURE_TOLERANCE: number = 60_000;

/** What a driver holds per key; `v` changes whenever the shape of `value` does. */
export interface Envelope<T> {
  v: 1;
  loadedAt: number;
  value: T;
}

/**
 * The driver key for `key` in the cache `name`: `unauth:<name>:<sha256 hex>`, fixed length and
 * plain ASCII whatever `key` holds, so no key can imitate another namespace.
 */
export async function driverKey(name: string, key: string): Promise<string> {
  return `unauth:${name}:${await hash(key, { algorithm: "SHA-256", returnAs: "hex" })}`;
}

/**
 * The value of a driver entry still within `maxAge` of `now`, without prototype-polluting keys and
 * accepted by `check` (which throws on anything else); `undefined` for any other entry.
 */
export function readEnvelope<T>(
  raw: unknown,
  options: { now: number; maxAge: number; check: (value: unknown) => T },
): Envelope<T> | undefined {
  if (!isRecord(raw) || raw.v !== 1) return undefined;
  const { loadedAt } = raw;
  if (typeof loadedAt !== "number" || !Number.isFinite(loadedAt)) return undefined;
  if (loadedAt > options.now + FUTURE_TOLERANCE || options.now - loadedAt > options.maxAge) {
    return undefined;
  }
  const value = isRecord(raw.value) ? sanitizeObjectCopy(raw.value) : raw.value;
  try {
    return { v: 1, loadedAt, value: options.check(value) };
  } catch {
    return undefined;
  }
}

/** Whether `envelope`, measured as UTF-8 JSON, fits a driver's `maxEntryBytes`; any fits without one. */
export function fitsDriver(envelope: unknown, maxEntryBytes: number | undefined): boolean {
  if (maxEntryBytes === undefined) return true;
  return new TextEncoder().encode(JSON.stringify(envelope)).byteLength <= maxEntryBytes;
}
