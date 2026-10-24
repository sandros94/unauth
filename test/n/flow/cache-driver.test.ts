import { describe, expect, expectTypeOf, it } from "vitest";

import { PROVIDER_CACHE_TTL } from "../../../src/n/flow/_internal/cache/load.ts";
import { type CacheDriver, discover, fetchJwks, isUnauthError } from "../../../src/n/index.ts";
import { createFakeProvider } from "./_fake-provider.ts";

const NOW = Date.UTC(2026, 9, 1, 12);
const at = (ms: number) => () => NOW + ms;

/** ocache 0.3.0 `StorageInterface`, copied by shape (src/storage.ts:6-29). */
interface OcacheStorageInterface {
  get<T = unknown>(key: string): T | null | Promise<T | null>;
  // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- copied shape
  set<T = unknown>(key: string, value: T, opts?: { ttl?: number }): void | Promise<void>;
  maxEntryBytes?: number;
  binary?: boolean;
}

/** The part of an unstorage `Storage` an ocache adapter calls. */
interface UnstorageLike {
  getItem<U = unknown>(key: string): Promise<U | null>;
  // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- copied shape
  setItem<U = unknown>(key: string, value: U, opts?: { ttl?: number }): Promise<void>;
  removeItem(key: string): Promise<void>;
}

function memoryDriver(options: { async?: boolean; maxEntryBytes?: number } = {}) {
  const entries = new Map<string, unknown>();
  const sets: { key: string; value: unknown; ttl: number | undefined }[] = [];
  let gets = 0;
  const driver: CacheDriver = {
    get: <T>(key: string) => {
      gets++;
      const value = (entries.get(key) ?? null) as T | null;
      return options.async ? Promise.resolve(value) : value;
    },
    set: (key, value, opts) => {
      sets.push({ key, value, ttl: opts?.ttl });
      entries.set(key, value);
      return options.async ? Promise.resolve() : undefined;
    },
    maxEntryBytes: options.maxEntryBytes,
  };
  return { driver, entries, sets, gets: () => gets };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("CacheDriver parity with ocache's StorageInterface", () => {
  it("accepts any ocache storage and is one", () => {
    expectTypeOf<OcacheStorageInterface>().toExtend<CacheDriver>();
    expectTypeOf<CacheDriver>().toExtend<OcacheStorageInterface>();
  });

  it("accepts the ocache unstorage adapter as is", () => {
    const unstorage = {} as UnstorageLike;
    const adapter: OcacheStorageInterface = {
      get: (key) => unstorage.getItem(key),
      set: (key, value, options) =>
        value === null || value === undefined
          ? unstorage.removeItem(key)
          : unstorage.setItem(key, value, { ttl: options?.ttl }),
    };
    expectTypeOf(adapter).toExtend<CacheDriver>();
    const shim: CacheDriver = {
      get: (key) => unstorage.getItem(key),
      set: (key, value, options) => unstorage.setItem(key, value, options),
    };
    expectTypeOf(shim).toExtend<OcacheStorageInterface>();
  });

  it("hands a null-returning driver to ocache unchanged", () => {
    const { driver } = memoryDriver();
    expectTypeOf(driver).toExtend<OcacheStorageInterface>();
  });
});

describe("cache driver", () => {
  it("stores an envelope under a hashed key with a ttl in seconds, and force skips the read", async () => {
    const issuer = "https://driver-discovery.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver, sets, gets } = memoryDriver();

    const first = await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver });
    const again = await discover(issuer, {
      now: at(0),
      cache: driver,
      fetch: async () => {
        throw new Error("the driver should have answered");
      },
    });

    expect(sets).toHaveLength(1);
    expect(sets[0]!.key).toMatch(/^unauth:discovery:[0-9a-f]{64}$/);
    expect(sets[0]!.value).toEqual({ v: 1, loadedAt: NOW, value: first });
    expect(sets[0]!.ttl).toBe(600);
    expect(again).toEqual(first);
    expect(fake.requests).toHaveLength(1);

    const reads = gets();
    await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver, force: true });
    expect(gets()).toBe(reads);
    expect(fake.requests).toHaveLength(2);
    expect(sets).toHaveLength(2);
  });

  it("awaits a driver that answers with promises", async () => {
    const issuer = "https://driver-async.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver, sets } = memoryDriver({ async: true });

    const first = await fetchJwks(`${issuer}/jwks`, { fetch: fake.fetch, cache: driver });
    const second = await fetchJwks(`${issuer}/jwks`, { fetch: fake.fetch, cache: driver });

    expect(second).toEqual(first);
    expect(fake.jwksFetches()).toBe(1);
    expect(sets.map((set) => set.ttl)).toEqual([600]);
  });

  it("keeps discovery and JWK Set entries apart", async () => {
    const issuer = "https://driver-apart.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver } = memoryDriver();

    await discover(issuer, { fetch: fake.fetch, cache: driver });
    const error = await rejection(fetchJwks(issuer, { fetch: fake.fetch, cache: driver }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
  });

  it("shares one driver across fetch scopes", async () => {
    const issuer = "https://driver-scopes.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver } = memoryDriver();
    const other: typeof fetch = (input, init) => fake.fetch(input, init);

    await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver });
    await discover(issuer, { fetch: other, now: at(0), cache: driver });

    expect(fake.requests).toHaveLength(1);
  });

  it("dedupes concurrent loads through a missing async driver", async () => {
    const issuer = "https://driver-dedupe.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver, sets } = memoryDriver({ async: true });

    await Promise.all([
      discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver }),
      discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver }),
    ]);

    expect(fake.requests).toHaveLength(1);
    expect(sets).toHaveLength(1);
  });

  it("propagates a throwing driver unchanged, fetching nothing", async () => {
    const issuer = "https://driver-throws.idp.test";
    const fake = await createFakeProvider({ issuer });
    const failure = new Error("kv down");
    const driver: CacheDriver = {
      get: () => {
        throw failure;
      },
      set: () => {},
    };

    expect(await rejection(discover(issuer, { fetch: fake.fetch, cache: driver }))).toBe(failure);
    expect(fake.requests).toHaveLength(0);
  });

  it("skips set for an envelope over the driver's maxEntryBytes, keeping it in memory", async () => {
    const issuer = "https://driver-small.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver, sets } = memoryDriver({ maxEntryBytes: 64 });

    await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver });
    await discover(issuer, { fetch: fake.fetch, now: at(1), cache: driver });

    expect(sets).toHaveLength(0);
    expect(fake.requests).toHaveLength(1);
  });

  it("sets an envelope within the driver's maxEntryBytes", async () => {
    const issuer = "https://driver-large.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver, sets } = memoryDriver({ maxEntryBytes: 1_000_000 });

    await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver });

    expect(sets).toHaveLength(1);
  });

  it("does not let a cached __proto__ key pollute", async () => {
    const issuer = "https://driver-proto.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver, entries } = memoryDriver();
    await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver });
    const [key, stored] = [...entries][0]!;
    const value = JSON.parse(
      JSON.stringify(stored).replace('"value":{', '"value":{"__proto__":{"polluted":true},'),
    ) as Record<string, unknown>;
    expect(Object.hasOwn(value.value as object, "__proto__")).toBe(true);
    entries.set(key, value);

    const hit = await discover(issuer, { fetch: fake.fetch, now: at(1), cache: driver });

    expect(Object.hasOwn(hit, "__proto__")).toBe(false);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(fake.requests).toHaveLength(1);
  });
});

describe("junk from the driver", () => {
  const metadata = (issuer: string) => ({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
  });

  it.each<[string, (issuer: string) => unknown]>([
    ["a string", () => "garbage"],
    ["null", () => null],
    ["another envelope version", (issuer) => ({ v: 2, loadedAt: NOW, value: metadata(issuer) })],
    [
      "an expired envelope",
      (issuer) => ({ v: 1, loadedAt: NOW - PROVIDER_CACHE_TTL - 1, value: metadata(issuer) }),
    ],
    [
      "an envelope from the future",
      (issuer) => ({ v: 1, loadedAt: NOW + 60_001, value: metadata(issuer) }),
    ],
    [
      "another issuer's document",
      () => ({ v: 1, loadedAt: NOW, value: metadata("https://evil.test") }),
    ],
    [
      "a document without token_endpoint",
      (issuer) => ({
        v: 1,
        loadedAt: NOW,
        value: { ...metadata(issuer), token_endpoint: undefined },
      }),
    ],
  ])("treats %s as a miss and overwrites it", async (label, junk) => {
    const issuer = `https://junk-${label.replaceAll(" ", "-").replaceAll("'", "")}.idp.test`;
    const fake = await createFakeProvider({ issuer });
    const { driver, entries, sets } = memoryDriver();
    await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver });
    const [key] = [...entries.keys()];
    entries.set(key!, junk(issuer));

    const document = await discover(issuer, { fetch: fake.fetch, now: at(0), cache: driver });

    expect(document.issuer).toBe(issuer);
    expect(fake.requests).toHaveLength(2);
    expect(sets).toHaveLength(2);
    expect(entries.get(key!)).toMatchObject({ v: 1, value: { issuer } });
  });

  it("treats a JWK Set without a keys array as a miss", async () => {
    const issuer = "https://junk-jwks.idp.test";
    const fake = await createFakeProvider({ issuer });
    const { driver, entries } = memoryDriver();
    await fetchJwks(`${issuer}/jwks`, { fetch: fake.fetch, now: at(0), cache: driver });
    const [key] = [...entries.keys()];
    entries.set(key!, { v: 1, loadedAt: NOW, value: { keys: "x" } });

    const set = await fetchJwks(`${issuer}/jwks`, { fetch: fake.fetch, now: at(0), cache: driver });

    expect(Array.isArray(set.keys)).toBe(true);
    expect(fake.jwksFetches()).toBe(2);
  });
});
