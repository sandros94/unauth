/**
 * The application's store, member for member ocache's `StorageInterface`, so an ocache storage is
 * a `CacheDriver` as is: `unauth/n` keeps provider documents (discovery, JWK Sets) in one, shared
 * across instances and by every `fetch`; `unauth/session` keeps opaque session records in one.
 *
 * - `get(key)` returns the stored value; `null` or `undefined` is a miss.
 * - `set(key, value, { ttl })` stores it; `ttl` is in seconds and advisory. `set(key, null)` removes
 *   the entry, as in ocache: a driver that keeps `null` instead answers the next `get` with a miss.
 *
 * `unauth/n` stores the envelope `{ v: 1, loadedAt, value }` under `unauth:<cache>:<sha256 hex>`
 * and re-validates every hit (shape, age, issuer): a driver that drops `ttl` or returns junk
 * costs a refetch, never trust. An entry whose JSON exceeds `maxEntryBytes` is not set and stays
 * in this instance's memory. A driver that throws fails the call. `binary` is ignored: entries
 * are JSON.
 *
 * @example
 * // a storage whose methods are named differently
 * const cache: CacheDriver = {
 *   get: (key) => storage.getItem(key),
 *   set: (key, value, options) => storage.setItem(key, value, options),
 * };
 * discover(issuer, { cache });
 */
export interface CacheDriver {
  get<T = unknown>(key: string): T | null | Promise<T | null>;
  // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- `T` types the stored value at the call site, as in `get`
  set<T = unknown>(key: string, value: T, opts?: { ttl?: number }): void | Promise<void>;
  maxEntryBytes?: number;
  binary?: boolean;
}
