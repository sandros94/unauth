import { describe, expect, it, vi } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import { type FlowKey, flowKeyResolver } from "../../src/n/_flow-key.ts";
import { isUnauthError } from "../../src/n/index.ts";

const PEM_REMEDY = /importPEM\(pem, alg\)[\s\S]*deriveKey/;

function thrown(run: () => unknown): unknown {
  try {
    run();
  } catch (error) {
    return error;
  }
  throw new Error("expected a throw");
}

async function refusal(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("flowKeyResolver", () => {
  it("passes a direct key through untouched", async () => {
    const key = await generateJWK("A256GCM");
    const resolve = flowKeyResolver(key);

    expect(await resolve()).toBe(key);
    expect(await resolve()).toBe(key);
  });

  it("calls a key callback once and hands its key to every later call", async () => {
    const key = await generateJWK("A256GCM");
    const callback = vi.fn(async (): Promise<FlowKey> => key);
    const resolve = flowKeyResolver(callback);

    expect(callback).not.toHaveBeenCalled();
    const [first, second] = await Promise.all([resolve(), resolve()]);
    expect(first).toBe(key);
    expect(second).toBe(key);
    expect(await resolve()).toBe(key);
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it("takes a synchronous key callback", async () => {
    const key = await generateJWK("A256GCM");

    expect(await flowKeyResolver(() => key)()).toBe(key);
  });

  it("drops a rejected callback, so the next call tries again", async () => {
    const key = await generateJWK("A256GCM");
    const callback = vi
      .fn<() => Promise<JWK_oct<"A256GCM">>>()
      .mockRejectedValueOnce(new Error("vault unavailable"))
      .mockResolvedValue(key);
    const resolve = flowKeyResolver(callback);

    await expect(resolve()).rejects.toThrow("vault unavailable");
    expect(await resolve()).toBe(key);
    expect(await resolve()).toBe(key);
    expect(callback).toHaveBeenCalledTimes(2);
  });

  it("refuses a missing key where the resolver is made", () => {
    // @ts-expect-error `key` is required
    const error = thrown(() => flowKeyResolver(undefined));

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((error as Error).message).toMatch(/`key`/);
  });

  it("refuses a string key where the resolver is made, naming importPEM and deriveKey", () => {
    // @ts-expect-error a string is not a key
    const error = thrown(() => flowKeyResolver("-----BEGIN PRIVATE KEY-----"));

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((error as Error).message).toMatch(PEM_REMEDY);
  });

  it("refuses a callback's string when it resolves, and retries on the next call", async () => {
    const key = await generateJWK("A256GCM");
    const callback = vi
      .fn<() => Promise<FlowKey>>()
      // @ts-expect-error a string is not a key
      .mockResolvedValueOnce("a-flow-secret-of-at-least-32-characters")
      .mockResolvedValue(key);
    const resolve = flowKeyResolver(callback);

    const error = await refusal(resolve());
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((error as Error).message).toMatch(PEM_REMEDY);
    expect(await resolve()).toBe(key);
  });

  it("refuses a synchronous callback returning a string the same way", async () => {
    // @ts-expect-error a string is not a key
    const resolve = flowKeyResolver(() => "a-flow-secret-of-at-least-32-characters");

    const error = await refusal(resolve());
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((error as Error).message).toMatch(PEM_REMEDY);
  });

  it("refuses a callback resolving to nothing", async () => {
    // @ts-expect-error the callback must return a key
    const error = await refusal(flowKeyResolver(async () => undefined)());

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });
});
