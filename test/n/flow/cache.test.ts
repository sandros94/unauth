import { describe, expect, it, vi } from "vitest";

import {
  LOAD_FAILURE_COOLDOWN,
  MAX_ENTRIES,
  PROVIDER_CACHE_TTL,
  loadCache,
} from "../../../src/n/flow/_internal/cache/load.ts";
import { type Fetch, discover } from "../../../src/n/index.ts";

const NOW = Date.UTC(2026, 9, 1, 12);
const at = (ms: number) => () => NOW + ms;

function textCache(options?: { max?: number }) {
  return loadCache<string>({
    name: "test",
    max: options?.max,
    check: (value) => {
      if (typeof value !== "string") throw new TypeError("not a string");
      return value;
    },
  });
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("provider document cache", () => {
  it("never serves one fetch's document to another", async () => {
    const issuer = "https://cache-scope.idp.test";
    const documentFrom =
      (token: string): Fetch =>
      async () =>
        Response.json({
          issuer,
          authorization_endpoint: `${issuer}/${token}/a`,
          token_endpoint: `${issuer}/${token}/t`,
          jwks_uri: `${issuer}/${token}/j`,
        });

    const first = await discover(issuer, { fetch: documentFrom("one"), now: at(0) });
    const second = await discover(issuer, { fetch: documentFrom("two"), now: at(0) });

    expect(first.token_endpoint).toBe(`${issuer}/one/t`);
    expect(second.token_endpoint).toBe(`${issuer}/two/t`);
  });

  it("purges expired entries when another is stored", async () => {
    const cache = textCache();
    const scope = {};
    await cache.get("a", async () => "a", { now: at(0), scope });
    await cache.get("b", async () => "b", { now: at(0), scope });
    expect(cache.size(scope)).toBe(2);

    await cache.get("c", async () => "c", { now: at(PROVIDER_CACHE_TTL + 1), scope });

    expect(cache.size(scope)).toBe(1);
  });

  it("reloads an entry past its ttl", async () => {
    const cache = textCache();
    let loads = 0;
    const load = async () => `v${++loads}`;
    await cache.get("a", load, { now: at(0) });
    expect(await cache.get("a", load, { now: at(PROVIDER_CACHE_TTL) })).toBe("v1");
    expect(await cache.get("a", load, { now: at(PROVIDER_CACHE_TTL + 1) })).toBe("v2");
  });

  it("holds at most its cap, dropping the least recently used", async () => {
    const cache = textCache({ max: 3 });
    const scope = {};
    let loads = 0;
    const load = async () => `v${++loads}`;
    for (const key of ["a", "b", "c"]) await cache.get(key, load, { now: at(0), scope });
    await cache.get("a", load, { now: at(0), scope });
    await cache.get("d", load, { now: at(0), scope });

    expect(cache.size(scope)).toBe(3);
    expect(loads).toBe(4);
    await cache.get("a", load, { now: at(0), scope });
    expect(loads).toBe(4);
    await cache.get("b", load, { now: at(0), scope });
    expect(loads).toBe(5);
  });

  it("stays at 256 entries under a flood of 10k keys", async () => {
    const cache = textCache();
    const scope = {};
    let loads = 0;
    for (let index = 0; index < 10_000; index++) {
      await cache.get(`https://issuer-${index}.test`, async () => `v${++loads}`, {
        now: at(0),
        scope,
      });
    }
    expect(MAX_ENTRIES).toBe(256);
    expect(cache.size(scope)).toBe(256);
    expect(loads).toBe(10_000);
  });

  it("keeps a hot key through a flood of cold ones", async () => {
    const cache = textCache();
    const scope = {};
    let hot = 0;
    await cache.get("hot", async () => `hot${++hot}`, { now: at(0), scope });
    for (let index = 0; index < 300; index++) {
      await cache.get("hot", async () => `hot${++hot}`, { now: at(0), scope });
      await cache.get(String(index), async () => "cold", { now: at(0), scope });
    }
    expect(hot).toBe(1);
  });

  it("shares one pending load between concurrent callers", async () => {
    const cache = textCache();
    let loads = 0;
    const load = async () => `v${++loads}`;
    const values = await Promise.all([
      cache.get("a", load, { now: at(0) }),
      cache.get("a", load, { now: at(0) }),
    ]);
    expect(values).toEqual(["v1", "v1"]);
    expect(loads).toBe(1);
  });
});

describe("failure cooldown", () => {
  it("rethrows a failed load for five seconds without loading, force included", async () => {
    const cache = textCache();
    const failure = new Error("down");
    let loads = 0;
    const load = async () => {
      loads++;
      throw failure;
    };

    expect(await rejection(cache.get("a", load, { now: at(0) }))).toBe(failure);
    expect(await rejection(cache.get("a", load, { now: at(1000) }))).toBe(failure);
    expect(await rejection(cache.get("a", load, { now: at(1000), force: true }))).toBe(failure);
    expect(loads).toBe(1);

    expect(await rejection(cache.get("a", load, { now: at(LOAD_FAILURE_COOLDOWN + 1) }))).toBe(
      failure,
    );
    expect(loads).toBe(2);
  });

  it("keeps a failure as a record that the sweep later drops", async () => {
    const cache = textCache();
    const scope = {};
    await rejection(cache.get("a", () => Promise.reject(new Error("x")), { now: at(0), scope }));
    expect(cache.size(scope)).toBe(1);

    await cache.get("b", async () => "b", { now: at(LOAD_FAILURE_COOLDOWN), scope });

    expect(cache.size(scope)).toBe(1);
  });

  it("never lets an older load's failure replace a newer load", async () => {
    const cache = textCache();
    let fail: (error: Error) => void = () => {};
    const older = cache.get("a", () => new Promise<string>((_r, reject) => (fail = reject)), {
      now: at(0),
    });
    const newer = await cache.get("a", async () => "new", { now: at(0), force: true });
    fail(new Error("late"));
    await rejection(older);

    let loads = 0;
    const again = await cache.get("a", async () => `v${++loads}`, { now: at(1) });
    expect(newer).toBe("new");
    expect(again).toBe("new");
    expect(loads).toBe(0);
  });
});

describe("force", () => {
  it("reloads unconditionally without a cooldown", async () => {
    const cache = textCache();
    let loads = 0;
    const load = async () => `v${++loads}`;
    await cache.get("a", load, { now: at(0) });
    expect(await cache.get("a", load, { now: at(0), force: true })).toBe("v2");
  });

  it("answers from cache inside the cooldown and reloads at its end", async () => {
    const cache = textCache();
    let loads = 0;
    const load = async () => `v${++loads}`;
    await cache.get("a", load, { now: at(0) });

    expect(await cache.get("a", load, { now: at(29_999), force: true, cooldown: 30_000 })).toBe(
      "v1",
    );
    expect(await cache.get("a", load, { now: at(30_000), force: true, cooldown: 30_000 })).toBe(
      "v2",
    );
  });
});

describe("callers that inject no fetch", () => {
  it("share one cache: the global fetch is asked once per document", async () => {
    const issuer = "https://global-scope.idp.test";
    const calls: string[] = [];
    const stub: Fetch = async (input) => {
      calls.push(String(input instanceof Request ? input.url : input));
      return Response.json({
        issuer,
        authorization_endpoint: `${issuer}/a`,
        token_endpoint: `${issuer}/t`,
        jwks_uri: `${issuer}/j`,
      });
    };
    vi.stubGlobal("fetch", stub);
    try {
      const first = await discover(issuer, { now: at(0) });
      const second = await discover(issuer, { now: at(1_000) });
      expect(first.token_endpoint).toBe(`${issuer}/t`);
      expect(second).toEqual(first);
      expect(calls).toEqual([`${issuer}/.well-known/openid-configuration`]);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("rethrow a failed load for the cooldown without asking the global fetch again", async () => {
    const issuer = "https://global-failure.idp.test";
    let calls = 0;
    vi.stubGlobal("fetch", async () => {
      calls += 1;
      return new Response("down", { status: 503 });
    });
    try {
      const first = await rejection(discover(issuer, { now: at(0) }));
      const second = await rejection(discover(issuer, { now: at(LOAD_FAILURE_COOLDOWN - 1) }));
      expect(second).toBe(first);
      expect(calls).toBe(1);
      await rejection(discover(issuer, { now: at(LOAD_FAILURE_COOLDOWN) }));
      expect(calls).toBe(2);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
