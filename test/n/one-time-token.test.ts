import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { isJWTError } from "unjwt/error";
import { type JWK_oct, defineJWSSession, generateJWK } from "unjwt/session";

import {
  type OneTimeTokenKeyLookup,
  UnauthError,
  createOpaqueToken,
  defineOneTimeToken,
  hashOpaqueToken,
  isUnauthError,
} from "../../src/n/index.ts";

let key: JWK_oct<"HS256">;

beforeAll(async () => {
  key = await generateJWK("HS256");
});

afterEach(() => {
  vi.useRealTimers();
});

function memoryConsume() {
  const used = new Set<string>();
  const consume = vi.fn(async ({ jti }: { jti: string; expiresAt: number; purpose: string }) => {
    if (used.has(jti)) return false;
    used.add(jti);
    return true;
  });
  return consume;
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("defineOneTimeToken", () => {
  it("opens a token once", async () => {
    const consume = memoryConsume();
    const reset = defineOneTimeToken<{ userId: string }>({
      key,
      maxAge: "15m",
      purpose: "password-reset",
      consume,
    });
    const token = await reset.issue({ userId: "u1" });

    await expect(reset.open(token)).resolves.toEqual({ userId: "u1" });
    const again = await rejection(reset.open(token));

    expect(isUnauthError(again, "ERR_AUTHN_TOKEN_USED")).toBe(true);
    expect(consume).toHaveBeenCalledTimes(2);
    const [args] = consume.mock.calls[0]!;
    expect(args).toMatchObject({ purpose: "password-reset" });
    expect(args.jti).toBeTypeOf("string");
    expect(args.expiresAt).toBeGreaterThan(Date.now());
  });

  it("refuses a token of another purpose without consuming it", async () => {
    const consume = memoryConsume();
    const invite = defineOneTimeToken<{ email: string }>({
      key,
      maxAge: "1D",
      purpose: "invite",
      consume,
    });
    const reset = defineOneTimeToken<{ email: string }>({
      key,
      maxAge: "1D",
      purpose: "password-reset",
      consume,
    });
    const token = await invite.issue({ email: "a@b.c" });

    const error = await rejection(reset.open(token));

    expect(isUnauthError(error, "ERR_AUTHN_TOKEN_PURPOSE")).toBe(true);
    expect(consume).not.toHaveBeenCalled();
    await expect(invite.open(token)).resolves.toEqual({ email: "a@b.c" });
  });

  it("throws ERR_AUTHN_TOKEN_INVALID for an expired, tampered or foreign token", async () => {
    const consume = memoryConsume();
    const link = defineOneTimeToken<{ email: string }>({
      key,
      maxAge: "15m",
      purpose: "magic-link",
      consume,
    });
    const token = await link.issue({ email: "a@b.c" });
    const other = defineOneTimeToken<{ email: string }>({
      key: await generateJWK("HS256"),
      maxAge: "15m",
      purpose: "magic-link",
      consume,
    });

    const tampered = `${token.slice(0, -2)}xx`;
    for (const candidate of [tampered, await other.issue({ email: "a@b.c" }), "nope"]) {
      expect(isUnauthError(await rejection(link.open(candidate)), "ERR_AUTHN_TOKEN_INVALID")).toBe(
        true,
      );
    }
    vi.useFakeTimers({ toFake: ["Date"], now: Date.now() + 16 * 60_000 });
    expect(isUnauthError(await rejection(link.open(token)), "ERR_AUTHN_TOKEN_INVALID")).toBe(true);
    expect(consume).not.toHaveBeenCalled();
  });

  it("keeps its purpose apart from the data, so a data field cannot change it", async () => {
    const consume = memoryConsume();
    const link = defineOneTimeToken<{ email: string; purpose?: string }>({
      key,
      maxAge: "15m",
      purpose: "magic-link",
      consume,
    });
    const token = await link.issue({ email: "a@b.c", purpose: "invite" });

    await expect(link.open(token)).resolves.toEqual({ email: "a@b.c", purpose: "invite" });
  });
});

describe("one-time token keys", () => {
  function header(token: string): Record<string, unknown> {
    const json = atob(token.split(".")[0]!.replaceAll("-", "+").replaceAll("_", "/"));
    return JSON.parse(json) as Record<string, unknown>;
  }

  function hmacKey(): Promise<CryptoKey> {
    return crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  }

  function linkOf(
    config: Omit<Parameters<typeof defineOneTimeToken>[0], "maxAge" | "purpose" | "consume">,
  ) {
    return defineOneTimeToken<{ email: string }>({
      ...config,
      maxAge: "15m",
      purpose: "magic-link",
      consume: memoryConsume(),
    });
  }

  it("signs with a JWK Set's first key and still opens what the others signed", async () => {
    const next = await generateJWK("HS256");
    const old = await linkOf({ key }).issue({ email: "old@b.c" });
    const rotated = linkOf({ key: { keys: [next, key] } });

    await expect(rotated.open(old)).resolves.toEqual({ email: "old@b.c" });
    const fresh = await rotated.issue({ email: "new@b.c" });
    expect(header(fresh)).toMatchObject({ kid: next.kid, typ: "unauth-ott+jwt" });
    await expect(linkOf({ key: next }).open(fresh)).resolves.toEqual({ email: "new@b.c" });
    const stale = await rejection(linkOf({ key }).open(fresh));
    expect(isUnauthError(stale, "ERR_AUTHN_TOKEN_INVALID")).toBe(true);
  });

  it("takes a CryptoKey once `jws` names its algorithm, and refuses it without", async () => {
    const cryptoKey = await hmacKey();
    const link = linkOf({ key: cryptoKey, jws: { alg: "HS256" } });
    const token = await link.issue({ email: "a@b.c" });

    expect(header(token)).toMatchObject({ alg: "HS256", typ: "unauth-ott+jwt" });
    await expect(link.open(token)).resolves.toEqual({ email: "a@b.c" });
    const { alg: _alg, ...bare } = await generateJWK("HS256");
    for (const unnamed of [cryptoKey, bare, { keys: [key, bare] }] as const) {
      let error: unknown;
      try {
        linkOf({ key: unnamed as JWK_oct<"HS256"> });
      } catch (thrown) {
        error = thrown;
      }
      expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
      expect((error as Error).message).toMatch(/naming no algorithm[\s\S]*"jws"/);
    }
  });

  it("opens under `jws` what a set entry naming no `alg` signed", async () => {
    const { alg: _alg, ...bare } = await generateJWK("HS256");
    const old = await linkOf({ key: bare, jws: { alg: "HS256" } }).issue({
      email: "a@b.c",
    });
    const set = { keys: [key, bare] };

    await expect(linkOf({ key: set, jws: { alg: "HS256" } }).open(old)).resolves.toEqual({
      email: "a@b.c",
    });
  });

  it("signs with a pair's private key and verifies with its public key", async () => {
    const pair = await generateJWK("ES256");
    const link = linkOf({ key: pair });
    const token = await link.issue({ email: "a@b.c" });

    expect(header(token)).toMatchObject({ alg: "ES256" });
    await expect(link.open(token)).resolves.toEqual({ email: "a@b.c" });
  });

  it("verifies under the key `onKeyLookup` picks by the token's `kid`, in place of `key`", async () => {
    const old = await generateJWK("HS256");
    const token = await linkOf({ key: old }).issue({ email: "a@b.c" });
    const lookups: unknown[] = [];
    const link = linkOf({
      key,
      onKeyLookup: (args) => {
        lookups.push(args);
        return { keys: [old] };
      },
    });

    await expect(link.open(token)).resolves.toEqual({ email: "a@b.c" });
    expect(lookups).toEqual([{ header: expect.objectContaining({ kid: old.kid }) }]);
    expect(Object.keys(lookups[0]!)).toEqual(["header"]);
    const unlooked = await rejection(linkOf({ key }).open(token));
    expect(isUnauthError(unlooked, "ERR_AUTHN_TOKEN_INVALID")).toBe(true);
  });

  it("refuses the token as invalid when `onKeyLookup` returns no key, or an empty JWK Set", async () => {
    const token = await linkOf({ key }).issue({ email: "a@b.c" });
    const lookups: OneTimeTokenKeyLookup[] = [() => undefined, () => ({ keys: [] })];

    for (const onKeyLookup of lookups) {
      const error = await rejection(linkOf({ key, onKeyLookup }).open(token));
      expect(isUnauthError(error, "ERR_AUTHN_TOKEN_INVALID")).toBe(true);
    }
  });

  it("propagates what `onKeyLookup` throws as it is, an `UnauthError` included, without consuming the token", async () => {
    const consume = memoryConsume();
    const token = await linkOf({ key }).issue({ email: "a@b.c" });
    const thrown = [
      new Error("kms down"),
      new UnauthError("[app] No such tenant.", "ERR_APP_TENANT"),
    ];

    const linkWith = (onKeyLookup: OneTimeTokenKeyLookup) =>
      defineOneTimeToken<{ email: string }>({
        key,
        onKeyLookup,
        maxAge: "15m",
        purpose: "magic-link",
        consume,
      });

    for (const down of thrown) {
      const link = linkWith(() => {
        throw down;
      });
      expect(await rejection(link.open(token))).toBe(down);
    }
    expect(consume).not.toHaveBeenCalled();
    await expect(linkWith(() => key).open(token)).resolves.toEqual({ email: "a@b.c" });
  });

  it("rejects with unjwt's `ERR_JWK_INVALID` a key `onKeyLookup` returns that cannot verify the token, without consuming it", async () => {
    const consume = memoryConsume();
    const token = await linkOf({ key }).issue({ email: "a@b.c" });
    const link = defineOneTimeToken<{ email: string }>({
      key,
      onKeyLookup: () => ({ kty: "oct", k: "AAAA", alg: "HS256" }),
      maxAge: "15m",
      purpose: "magic-link",
      consume,
    });

    expect(isJWTError(await rejection(link.open(token)), "ERR_JWK_INVALID")).toBe(true);
    expect(consume).not.toHaveBeenCalled();
  });

  it("refuses a JWK Set unjwt refuses, as a configuration error", async () => {
    const generated = await Promise.all(Array.from({ length: 9 }, () => generateJWK("HS256")));
    const keys = generated.map(({ kty, k, alg }) => ({ kty, k, alg }));
    let error: unknown;
    try {
      linkOf({ key: { keys } });
    } catch (thrown) {
      error = thrown;
    }

    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(isJWTError((error as Error).cause, "ERR_SESSION_CONFIG_INVALID")).toBe(true);
  });
});

describe("one-time token isolation", () => {
  it("never opens a JWS auth session token signed with the same key", async () => {
    const consume = memoryConsume();
    const link = defineOneTimeToken<{ purpose: string; data: { email: string } }>({
      key,
      maxAge: "15m",
      purpose: "magic-link",
      consume,
    });
    const sessions = defineJWSSession({ key, maxAge: "15m", cookie: false, sessionHeader: false });
    const forged = await sessions.issue({ purpose: "magic-link", data: { email: "a@b.c" } });

    const error = await rejection(link.open(forged));

    expect(isUnauthError(error, "ERR_AUTHN_TOKEN_INVALID")).toBe(true);
    expect(consume).not.toHaveBeenCalled();
  });

  it.each([[0], ["0s"], [-5], ["nonsense"]])("refuses maxAge %j at definition", (maxAge) => {
    let error: unknown;
    try {
      defineOneTimeToken({ key, maxAge: maxAge as "15m", purpose: "p", consume: () => true });
    } catch (error_) {
      error = error_;
    }
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });
});

describe("opaque tokens", () => {
  it.each([[8], [15], [16.5], [Number.NaN]])("refuses %j random bytes", async (bytes) => {
    const error = await rejection(createOpaqueToken({ bytes }));
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("creates a random token and the hash to store", async () => {
    const { token, hash } = await createOpaqueToken();

    expect(token).toMatch(/^[\w-]{43}$/);
    expect(hash).toBe(await hashOpaqueToken(token));
    expect(hash).not.toBe(token);
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)),
    );
    expect(hash).toBe(
      btoa(String.fromCharCode(...digest))
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/, ""),
    );
  });

  it("honours a byte length and stays unique", async () => {
    const a = await createOpaqueToken({ bytes: 16 });
    const b = await createOpaqueToken({ bytes: 16 });

    expect(a.token).toMatch(/^[\w-]{22}$/);
    expect(a.token).not.toBe(b.token);
  });
});
