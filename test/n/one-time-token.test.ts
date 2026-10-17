import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { type JWK_oct, defineJWSSession, generateJWK } from "unjwt/session";

import {
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
