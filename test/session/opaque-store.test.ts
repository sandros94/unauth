import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { CacheDriver } from "../../src/_internal/cache-driver.ts";
import {
  type OpaqueSessionRecord,
  type OpaqueSessionStore,
  kvSessionStore,
  readRecord,
} from "../../src/session/opaque-store.ts";

interface Data {
  userId: string;
}

const NOW = Date.UTC(2026, 0, 1, 12);
const HOUR = 60 * 60_000;

const record = (over?: Partial<OpaqueSessionRecord<Data>>): OpaqueSessionRecord<Data> => ({
  id: "sess_1",
  createdAt: NOW,
  updatedAt: NOW,
  expiresAt: NOW + HOUR,
  data: { userId: "u1" },
  ...over,
});

beforeEach(() => {
  vi.useFakeTimers({ now: NOW });
});
afterEach(() => {
  vi.useRealTimers();
});

type Make = () => { store: OpaqueSessionStore<Data> };

const stores: [string, Make][] = [
  [
    "kvSessionStore over a memory driver",
    () => ({ store: kvSessionStore<Data>(memoryDriver().driver) }),
  ],
  ["a one-statement SQL-like store", () => ({ store: tableStore().store })],
];

describe.each(stores)("%s", (_name, make) => {
  it("finds what it saved, null for a token it never saw", async () => {
    const { store } = make();
    expect(await store.find("t1")).toBeNull();
    await store.save("t1", record());
    expect(await store.find("t1")).toEqual(record());
    expect(await store.find("t2")).toBeNull();
  });

  it("save replaces", async () => {
    const { store } = make();
    await store.save("t1", record());
    await store.save("t1", record({ data: { userId: "u2" }, updatedAt: NOW + 1 }));
    expect(await store.find("t1")).toEqual(record({ data: { userId: "u2" }, updatedAt: NOW + 1 }));
  });

  it("touch moves the end and reports a missing session", async () => {
    const { store } = make();
    expect(await store.touch("t1", { updatedAt: NOW + 1, expiresAt: NOW + 2 * HOUR })).toBe(false);
    await store.save("t1", record());
    expect(await store.touch("t1", { updatedAt: NOW + 1, expiresAt: NOW + 2 * HOUR })).toBe(true);
    expect(await store.find("t1")).toEqual(
      record({ updatedAt: NOW + 1, expiresAt: NOW + 2 * HOUR }),
    );
    expect(await store.touch("t1", { updatedAt: NOW + 2, expiresAt: undefined })).toBe(true);
    expect((await store.find("t1"))?.expiresAt).toBeUndefined();
  });

  it("rekey moves the session: the old token names nothing, id and createdAt stay", async () => {
    const { store } = make();
    expect(await store.rekey("t1", "t2", { updatedAt: NOW + 1, expiresAt: NOW + HOUR })).toBe(
      false,
    );
    await store.save("t1", record());
    expect(await store.rekey("t1", "t2", { updatedAt: NOW + 1, expiresAt: NOW + HOUR })).toBe(true);
    expect(await store.find("t1")).toBeNull();
    expect(await store.find("t2")).toEqual(record({ updatedAt: NOW + 1 }));
  });

  it("delete is idempotent", async () => {
    const { store } = make();
    await store.delete("t1");
    await store.save("t1", record());
    await store.delete("t1");
    expect(await store.find("t1")).toBeNull();
    await store.delete("t1");
  });

  it("keeps sessions apart by token", async () => {
    const { store } = make();
    await store.save("t1", record());
    await store.save("t2", record({ id: "sess_2" }));
    await store.delete("t1");
    expect(await store.find("t2")).toEqual(record({ id: "sess_2" }));
  });
});

describe("kvSessionStore", () => {
  it("keys by prefix and raw token, with the record's end as ttl", async () => {
    const memory = memoryDriver();
    const store = kvSessionStore<Data>(memory.driver, { prefix: "s:" });
    await store.save("tok", record());
    expect([...memory.entries.keys()]).toEqual(["s:tok"]);
    expect(memory.entries.get("s:tok")?.ttl).toBe(3600);
    await store.touch("tok", { updatedAt: NOW, expiresAt: undefined });
    expect(memory.entries.get("s:tok")?.ttl).toBeUndefined();
  });

  it("treats junk under a key as a miss", async () => {
    const memory = memoryDriver();
    const store = kvSessionStore<Data>(memory.driver);
    memory.entries.set("tok", { value: "junk" });
    expect(await store.find("tok")).toBeNull();
    expect(await store.touch("tok", { updatedAt: NOW, expiresAt: NOW })).toBe(false);
  });
});

describe("readRecord", () => {
  it("accepts a record, with expiresAt absent, undefined or null", () => {
    expect(readRecord(record())).toEqual(record());
    expect(readRecord({ ...record(), expiresAt: undefined })).toEqual(
      record({ expiresAt: undefined }),
    );
    expect(readRecord({ ...record(), expiresAt: null })).toEqual(record({ expiresAt: undefined }));
  });

  it("refuses anything else", () => {
    for (const junk of [
      null,
      "x",
      [],
      {},
      { ...record(), id: "" },
      { ...record(), id: 1 },
      { ...record(), createdAt: "now" },
      { ...record(), updatedAt: Number.NaN },
      { ...record(), expiresAt: "soon" },
      { ...record(), data: null },
      { ...record(), data: [] },
    ]) {
      expect(readRecord(junk)).toBeNull();
    }
  });
});

function memoryDriver() {
  const entries = new Map<string, { value: unknown; ttl?: number }>();
  const state = { calls: 0 };
  const driver: CacheDriver = {
    // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- `CacheDriver.get` types the value at its call site
    get: <T>(key: string) => {
      state.calls += 1;
      const entry = entries.get(key);
      return entry ? (structuredClone(entry.value) as T) : null;
    },
    set: (key, value, options) => {
      state.calls += 1;
      if (value === null) entries.delete(key);
      else entries.set(key, { value: structuredClone(value), ttl: options?.ttl });
    },
  };
  return {
    driver,
    entries,
    get calls() {
      return state.calls;
    },
  };
}

/** A store that answers each verb with one "statement" over a table keyed by token. */
function tableStore() {
  const rows = new Map<string, OpaqueSessionRecord<Data>>();
  const state = { statements: 0 };
  const store: OpaqueSessionStore<Data> = {
    find: (token) => {
      state.statements += 1;
      return rows.get(token) ?? null;
    },
    save: (token, row) => {
      state.statements += 1;
      rows.set(token, structuredClone(row));
    },
    touch: (token, times) => {
      state.statements += 1;
      const row = rows.get(token);
      if (!row) return false;
      rows.set(token, { ...row, ...times });
      return true;
    },
    rekey: (from, to, times) => {
      state.statements += 1;
      const row = rows.get(from);
      if (!row) return false;
      rows.delete(from);
      rows.set(to, { ...row, ...times });
      return true;
    },
    delete: (token) => {
      state.statements += 1;
      rows.delete(token);
    },
  };
  return {
    store,
    get statements() {
      return state.statements;
    },
  };
}
