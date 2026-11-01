import { describe, expect, it } from "vitest";
import { thumbprint } from "unjwt/jwk";
import { defineJWESession } from "unjwt/session";
import { base64UrlParse } from "unjwt/utils";

import { deriveJWK, isUnauthError } from "../../src/n/index.ts";

const SECRET = "a-flow-secret-of-at-least-32-characters";
const INFO = "unauth:flow";

async function refusal(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("deriveJWK", () => {
  it("derives the same A256GCM key from the same secret and info", async () => {
    const first = await deriveJWK(SECRET, { info: INFO });
    const second = await deriveJWK(SECRET, { info: INFO });

    expect(first).toEqual({
      kty: "oct",
      k: expect.any(String),
      alg: "A256GCM",
      kid: expect.any(String),
    });
    expect(second).toEqual(first);
  });

  it("names the key by its RFC 7638 thumbprint, the same on every derivation and distinct per info", async () => {
    const flow = await deriveJWK(SECRET, { info: INFO });
    const other = await deriveJWK(SECRET, { info: "unauth:other" });

    expect(flow.kid).toBe(await thumbprint({ kty: "oct", k: flow.k }));
    expect((await deriveJWK(SECRET, { info: INFO })).kid).toBe(flow.kid);
    expect(other.kid).not.toBe(flow.kid);
  });

  it("derives a distinct key per info", async () => {
    const flow = await deriveJWK(SECRET, { info: INFO });
    const other = await deriveJWK(SECRET, { info: "unauth:other" });

    expect(other.k).not.toBe(flow.k);
  });

  it("derives a distinct key per secret", async () => {
    const first = await deriveJWK(SECRET, { info: INFO });
    const other = await deriveJWK(`${SECRET}!`, { info: INFO });

    expect(other.k).not.toBe(first.k);
  });

  it("derives 32 bytes of key material", async () => {
    const { k } = await deriveJWK(SECRET, { info: INFO });

    expect(base64UrlParse(k, { returnAs: "uint8array" })).toHaveLength(32);
  });

  it("refuses a secret shorter than 32 characters", async () => {
    const error = await refusal(deriveJWK("x".repeat(31), { info: INFO }));

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((error as Error).message).toMatch(/at least 32 characters, got 31/);
  });

  it("refuses an empty info", async () => {
    const error = await refusal(deriveJWK(SECRET, { info: "" }));

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((error as Error).message).toMatch(/`info`/);
  });

  it("seals and opens a JWE session", async () => {
    const definition = defineJWESession<{ user: string }>({
      key: await deriveJWK(SECRET, { info: INFO }),
      cookie: false,
      sessionHeader: false,
    });
    const reopened = defineJWESession<{ user: string }>({
      key: await deriveJWK(SECRET, { info: INFO }),
      cookie: false,
      sessionHeader: false,
    });

    const token = await definition.issue({ user: "ada" });
    const opened = await reopened.open(token);

    expect(opened.data).toEqual({ user: "ada" });
  });
});
