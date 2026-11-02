import { type Envelope, driverKey, fitsDriver, readEnvelope } from "./driver.ts";

/** How long a provider document (discovery, JWK Set) is trusted before it is fetched again. */
export const PROVIDER_CACHE_TTL: number = 10 * 60_000;

/** Entries one scope may hold before the least recently used goes. */
export const MAX_ENTRIES: number = 256;

/** How long a failed load is rethrown to every caller of its key without another fetch. */
export const LOAD_FAILURE_COOLDOWN: number = 5_000;

/** How old a JWK Set must be before a `force` (an unknown `kid`) may fetch it again. */
export const JWKS_REFRESH_COOLDOWN: number = 30_000;

/** The scope of callers that inject no `fetch`. */
const GLOBAL_SCOPE = {};

/**
 * The application's store for provider documents (discovery, JWK Sets), shared across instances
 * and by every `fetch`. Member for member ocache's `StorageInterface`, so an ocache storage is a
 * `CacheDriver` as is.
 *
 * - `get(key)` returns the stored value; `null` or `undefined` is a miss.
 * - `set(key, value, { ttl })` stores it; `ttl` is in seconds and advisory.
 *
 * unauth stores the envelope `{ v: 1, loadedAt, value }` under `unauth:<cache>:<sha256 hex>` and
 * re-validates every hit (shape, age, issuer): a driver that drops `ttl` or returns junk costs a
 * refetch, never trust. A driver that throws fails the call.
 *
 * An entry whose JSON exceeds `maxEntryBytes` is not set and stays in this instance's memory.
 * `binary` is ignored: entries are JSON.
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

/** Options of {@link LoadCache.get}. */
export interface LoadOptions {
  now: () => number;
  /** Keeps entries apart per injected `fetch`; the global scope by default. */
  scope?: object;
  /** Keeps settled values there instead of in memory, shared by every scope. */
  driver?: CacheDriver;
  /** Loads again although the held value is fresh; with `cooldown`, only once it is that old (ms). */
  force?: boolean;
  cooldown?: number;
}

/**
 * Loads kept apart per `fetch`, so a caller never gets a document another transport fetched:
 * concurrent callers share one load, a failure is rethrown for
 * {@link LOAD_FAILURE_COOLDOWN} without a load, expired entries are swept on insert and the least
 * recently used goes once a scope holds `max`. With a driver, memory holds only pending loads,
 * failures and values the driver could not take.
 */
export interface LoadCache<T> {
  get: (key: string, load: () => Promise<T>, options: LoadOptions) => Promise<T>;
  /** Entries held in memory for `scope` (the global one by default). */
  size: (scope?: object) => number;
}

type Entry<T> = { promise: Promise<T>; loadedAt: number } | { error: unknown; failedAt: number };

/**
 * A {@link LoadCache} named `name` in driver keys; `check` turns a driver hit back into a value
 * (the validator the fetch path uses), throwing on anything it would not have loaded.
 */
export function loadCache<T>(options: {
  name: string;
  check: (value: unknown, key: string) => T;
  max?: number;
}): LoadCache<T> {
  const max = options.max ?? MAX_ENTRIES;
  const scopes = new WeakMap<object, Map<string, Entry<T>>>();
  const entriesOf = (scope: object = GLOBAL_SCOPE) => {
    let entries = scopes.get(scope);
    if (!entries) {
      entries = new Map();
      scopes.set(scope, entries);
    }
    return entries;
  };
  return {
    get: async (key, load, gate) => {
      const { now, driver } = gate;
      const entries = entriesOf(gate.scope);
      const held = recall(entries, key, gate);
      if (held) return held;
      const name = driver && (await driverKey(options.name, key));
      if (driver && name && usable(0, gate)) {
        const raw = await driver.get(name);
        const joined = recall(entries, key, gate);
        if (joined) return joined;
        const check = (value: unknown) => options.check(value, key);
        const hit = readEnvelope(raw, { now: now(), maxAge: PROVIDER_CACHE_TTL, check });
        if (hit && usable(now() - hit.loadedAt, gate)) return hit.value;
      }
      sweep(entries, key, { now: now(), max });
      let stored = false;
      const promise = (async () => {
        const value = await load();
        const envelope: Envelope<T> = { v: 1, loadedAt: now(), value };
        if (driver && name && fitsDriver(envelope, driver.maxEntryBytes)) {
          await driver.set(name, envelope, { ttl: PROVIDER_CACHE_TTL / 1000 });
          stored = true;
        }
        return value;
      })();
      entries.set(key, { promise, loadedAt: now() });
      const holds = () => {
        const entry = entries.get(key);
        return entry !== undefined && "promise" in entry && entry.promise === promise;
      };
      promise.then(
        () => {
          if (stored && holds()) entries.delete(key);
        },
        (error: unknown) => {
          if (holds()) entries.set(key, { error, failedAt: now() });
        },
      );
      return promise;
    },
    size: (scope) => scopes.get(scope ?? GLOBAL_SCOPE)?.size ?? 0,
  };
}

/** The held load `gate` accepts, touched as most recently used; a recent failure is rethrown. */
function recall<T>(
  entries: Map<string, Entry<T>>,
  key: string,
  gate: LoadOptions,
): Promise<T> | undefined {
  const entry = entries.get(key);
  if (!entry) return undefined;
  if ("error" in entry) {
    if (gate.now() - entry.failedAt >= LOAD_FAILURE_COOLDOWN) return undefined;
    touch(entries, key, entry);
    throw entry.error;
  }
  if (!usable(gate.now() - entry.loadedAt, gate)) return undefined;
  touch(entries, key, entry);
  return entry.promise;
}

/** Whether a value `age` ms old answers the call: fresh, and inside any `force` cooldown. */
function usable(age: number, { force, cooldown }: LoadOptions): boolean {
  // Never stale-while-revalidate: a stale JWK Set keeps serving revoked keys.
  return age <= PROVIDER_CACHE_TTL && (!force || (cooldown !== undefined && age < cooldown));
}

function touch<T>(entries: Map<string, Entry<T>>, key: string, entry: Entry<T>): void {
  entries.delete(key);
  entries.set(key, entry);
}

/** Drops expired loads and failures, then the least recently used until `key` fits. */
function sweep<T>(
  entries: Map<string, Entry<T>>,
  key: string,
  { now, max }: { now: number; max: number },
): void {
  for (const [name, entry] of entries) {
    const expired =
      "error" in entry
        ? now - entry.failedAt >= LOAD_FAILURE_COOLDOWN
        : now - entry.loadedAt > PROVIDER_CACHE_TTL;
    if (expired) entries.delete(name);
  }
  entries.delete(key);
  while (entries.size >= max) {
    const oldest = entries.keys().next();
    if (oldest.done) break;
    entries.delete(oldest.value);
  }
}
