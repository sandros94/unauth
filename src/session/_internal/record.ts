import { sanitizeObjectCopy } from "unsecure/sanitize";
import type { CacheDriver } from "../../_internal/cache-driver.ts";
import { isRecord } from "../../_internal/shared.ts";
import type { OpaqueSessionRecord } from "../opaque-session.ts";

/** A record read back: the live one, or why the key holds none. */
export type ReadRecord<TData extends object> =
  | { record: OpaqueSessionRecord<TData>; reason?: undefined }
  | { record?: undefined; reason: "unknown" | "expired" };

/** The store's records, keyed by `prefix` and the token's hash. */
export interface RecordStore<TData extends object> {
  /** The live record under `id`; an expired or unreadable one is removed and reported. */
  read(id: string): Promise<ReadRecord<TData>>;
  /** Stores `record`, with a `ttl` hint until its `expiresAt`. */
  write(id: string, record: OpaqueSessionRecord<TData>): Promise<void>;
  remove(id: string): Promise<void>;
}

export function recordStore<TData extends object>(
  store: CacheDriver,
  options: { prefix: string; now: () => number },
): RecordStore<TData> {
  const key = (id: string) => `${options.prefix}${id}`;
  return {
    read: async (id) => {
      const raw = await store.get(key(id));
      if (raw === null || raw === undefined) return { reason: "unknown" };
      const now = options.now();
      const record = readRecord<TData>(raw);
      if (record && record.expiresAt > now) return { record };
      await store.set(key(id), null);
      return { reason: record ? "expired" : "unknown" };
    },
    write: async (id, record) => {
      const ttl = Math.max(1, Math.ceil((record.expiresAt - options.now()) / 1000));
      await store.set(key(id), record, { ttl });
    },
    remove: async (id) => {
      await store.set(key(id), null);
    },
  };
}

function readRecord<TData extends object>(raw: unknown): OpaqueSessionRecord<TData> | undefined {
  if (!isRecord(raw)) return undefined;
  const { createdAt, updatedAt, expiresAt, data } = raw;
  if (!isTime(createdAt) || !isTime(updatedAt) || !isTime(expiresAt) || !isRecord(data)) {
    return undefined;
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion -- the record under a token's hash is what this session's `update()` or `issue()` wrote: the application's `TData`
  return { createdAt, updatedAt, expiresAt, data: sanitizeObjectCopy(data) as TData };
}

function isTime(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}
