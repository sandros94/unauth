import type { CacheDriver } from "../_internal/cache-driver.ts";
import { isRecord } from "../_internal/shared.ts";

type Awaitable<T> = T | Promise<T>;

/** What a store holds for one session. Times are ms since the epoch. */
export interface OpaqueSessionRecord<TData> {
  /** The session's id, minted at creation and kept across `rotate()`: what lists and audits name. */
  id: string;
  /** When the session was created; an absolute lifetime counts from here. Never moves. */
  createdAt: number;
  /** When the session was last written or extended; an idle lifetime counts from here. */
  updatedAt: number;
  /** When the session ends, `undefined` for never: the sooner of its absolute and idle ends. */
  expiresAt: number | undefined;
  data: TData;
}

/** The times a store writes when a session is extended or moved under a new token. */
export interface OpaqueSessionTimes {
  updatedAt: number;
  expiresAt: number | undefined;
}

/**
 * Where sessions live, keyed by the token the client holds, as the client holds it: whether the
 * store keeps the token, its hash or something else is the store's business, and so is the row
 * shape. Each verb is one statement on a SQL store; {@link kvSessionStore} builds them over a
 * key-value `CacheDriver`. A store that throws fails the call.
 */
export interface OpaqueSessionStore<TData> {
  /** The record under `token`, `null` for none. The session checks `expiresAt` itself. */
  find(token: string): Awaitable<OpaqueSessionRecord<TData> | null>;
  /** Stores `record` under `token`, replacing what was there. */
  save(token: string, record: OpaqueSessionRecord<TData>): Awaitable<void>;
  /** Moves the end of the session under `token`; `false` when there is none to move. */
  touch(token: string, times: OpaqueSessionTimes): Awaitable<boolean>;
  /** Moves the session from `from` to `to`, `from` naming nothing after; `false` when there is none. */
  rekey(from: string, to: string, times: OpaqueSessionTimes): Awaitable<boolean>;
  /** Removes the session under `token`; nothing there is no error. */
  delete(token: string): Awaitable<void>;
}

/** Options of {@link kvSessionStore}. */
export interface KvSessionStoreOptions {
  /** What every key starts with. @default "" */
  prefix?: string;
}

/**
 * An {@link OpaqueSessionStore} over a key-value {@link CacheDriver} (an ocache storage, a KV
 * namespace, Redis, memory): one entry per token, the token as the key after `prefix`, the record
 * as the value, the driver's `ttl` hint set to the record's end. `touch` and `rekey` are a read and
 * a write; the driver's own consistency decides what a concurrent reader sees in between.
 */
export function kvSessionStore<TData>(
  driver: CacheDriver,
  options?: KvSessionStoreOptions,
): OpaqueSessionStore<TData> {
  const prefix = options?.prefix ?? "";
  const key = (token: string) => `${prefix}${token}`;
  const put = (token: string, record: OpaqueSessionRecord<TData>) => {
    const ttl =
      record.expiresAt === undefined
        ? undefined
        : Math.max(1, Math.ceil((record.expiresAt - Date.now()) / 1000));
    return driver.set(key(token), record, ttl === undefined ? undefined : { ttl });
  };
  return {
    find: async (token) => readRecord<TData>(await driver.get(key(token))),
    save: async (token, record) => {
      await put(token, record);
    },
    touch: async (token, times) => {
      const record = readRecord<TData>(await driver.get(key(token)));
      if (!record) return false;
      await put(token, { ...record, ...times });
      return true;
    },
    rekey: async (from, to, times) => {
      const record = readRecord<TData>(await driver.get(key(from)));
      if (!record) return false;
      await put(to, { ...record, ...times });
      await driver.set(key(from), null);
      return true;
    },
    delete: async (token) => {
      await driver.set(key(token), null);
    },
  };
}

/**
 * `raw` as a session record when it has the shape of one, `null` otherwise: a store answering junk
 * (a corrupted entry, another kind of value under the key) is a miss, never a session.
 */
export function readRecord<TData>(raw: unknown): OpaqueSessionRecord<TData> | null {
  if (!isRecord(raw)) return null;
  const { id, createdAt, updatedAt, expiresAt, data } = raw;
  if (typeof id !== "string" || id === "") return null;
  if (!isTime(createdAt) || !isTime(updatedAt)) return null;
  if (expiresAt !== undefined && expiresAt !== null && !isTime(expiresAt)) return null;
  if (!isRecord(data)) return null;
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the record under a token is what this session's `update()` or `issue()` wrote: the application's `TData`
  return { id, createdAt, updatedAt, expiresAt: expiresAt ?? undefined, data: data as TData };
}

function isTime(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}
