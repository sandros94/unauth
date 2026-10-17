import { describe, expect, it } from "vitest";

import { type Fetch, readObject } from "../../../src/n/flow/_http.ts";
import { getJson } from "../../../src/n/flow/_http-json.ts";
import { PROVIDER_DOCUMENT_MAX_BYTES } from "../../../src/n/flow/_http-body.ts";
import { exchangeCode, isUnauthError, oauth2 } from "../../../src/n/index.ts";

const URL_ = "https://idp.test/doc";

function recording(answer: (init: RequestInit | undefined) => Promise<Response>) {
  const inits: (RequestInit | undefined)[] = [];
  const fetch: Fetch = (_input, init) => {
    inits.push(init);
    return answer(init);
  };
  return { fetch, inits };
}

/** A body that hands out `chunks` one per pull and counts the pulls. */
function streamed(chunks: Uint8Array[]) {
  let pulls = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        pulls++;
        const chunk = chunks.shift();
        if (chunk) controller.enqueue(chunk);
        else controller.close();
      },
    },
    { highWaterMark: 0 },
  );
  return { body, pulls: () => pulls };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("getJson", () => {
  it("sends an abort signal and refuses redirects", async () => {
    const { fetch, inits } = recording(async () => Response.json({ ok: true }));

    await getJson(URL_, { fetch, label: "document" });

    expect(inits[0]?.redirect).toBe("error");
    expect(inits[0]?.signal).toBeInstanceOf(AbortSignal);
  });

  it("gives up on a provider that never answers, aborting the request", async () => {
    const { fetch, inits } = recording(() => new Promise<Response>(() => {}));
    const started = Date.now();

    const error = await rejection(getJson(URL_, { fetch, label: "document", timeout: 20 }));

    expect(Date.now() - started).toBeLessThan(500);
    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toMatch(/did not answer within 20 ms/);
    expect(inits[0]?.signal?.aborted).toBe(true);
  });

  it("gives up on a body that never ends", async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new TextEncoder().encode('{"a":'));
      },
    });
    const { fetch } = recording(async () => new Response(body));

    const error = await rejection(getJson(URL_, { fetch, label: "document", timeout: 20 }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toMatch(/did not answer within 20 ms/);
  });

  it("maps a fetch that rejects on abort to the same deadline error", async () => {
    const { fetch } = recording(
      (init) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(init.signal?.reason));
        }),
    );

    const error = await rejection(getJson(URL_, { fetch, label: "document", timeout: 20 }));

    expect((error as Error).message).toMatch(/did not answer within 20 ms/);
  });

  it("refuses an oversized body streamed without a length", async () => {
    const chunk = new Uint8Array(64 * 1024).fill(0x20);
    const { body } = streamed([chunk, chunk, chunk, chunk, chunk]);
    const { fetch } = recording(async () => new Response(body));

    const error = await rejection(getJson(URL_, { fetch, label: "document" }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toMatch(/more than the 262144 bytes allowed/);
  });

  it("refuses a declared oversized body without reading it", async () => {
    const { body, pulls } = streamed([new TextEncoder().encode("{}")]);
    const { fetch } = recording(
      async () => new Response(body, { headers: { "content-length": "999999" } }),
    );

    const error = await rejection(getJson(URL_, { fetch, label: "document" }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toMatch(/more than the 262144 bytes allowed/);
    expect(pulls()).toBe(0);
  });

  it("accepts a body of exactly the cap", async () => {
    const padding = "x".repeat(PROVIDER_DOCUMENT_MAX_BYTES - '{"a":""}'.length);
    const text = `{"a":"${padding}"}`;
    expect(new TextEncoder().encode(text).length).toBe(PROVIDER_DOCUMENT_MAX_BYTES);
    const { fetch } = recording(async () => new Response(text));

    await expect(getJson(URL_, { fetch, label: "document" })).resolves.toEqual({ a: padding });
  });

  it("refuses bytes that are not UTF-8", async () => {
    const { fetch } = recording(async () => new Response(new Uint8Array([0x7b, 0xff, 0x7d])));

    const error = await rejection(getJson(URL_, { fetch, label: "document" }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toMatch(/did not answer JSON/);
  });

  it("names the status of a failed answer", async () => {
    const { fetch } = recording(async () => new Response("down", { status: 503 }));

    const error = await rejection(getJson(URL_, { fetch, label: "document" }));

    expect((error as Error).message).toMatch(/answered 503/);
  });
});

describe("readObject", () => {
  const oversized = () => {
    const chunk = new Uint8Array(60 * 1024).fill(0x20);
    return streamed([chunk, chunk, chunk, chunk, chunk]).body;
  };

  it("tells a body over the cap from one that is not an object", async () => {
    await expect(readObject(new Response(oversized()))).resolves.toEqual({
      tooLarge: PROVIDER_DOCUMENT_MAX_BYTES,
    });
    await expect(readObject(new Response("[1]"))).resolves.toEqual({ object: undefined });
  });

  it("still reads a JSON object", async () => {
    await expect(readObject(Response.json({ a: 1 }))).resolves.toEqual({ object: { a: 1 } });
  });

  it("makes exchangeCode name an oversized token response", async () => {
    const provider = oauth2({
      id: "big",
      clientId: "c",
      clientSecret: "s",
      authorization: "https://idp.test/authorize",
      token: "https://idp.test/token",
      profile: () => ({ subject: "s", profile: {} }),
    });

    const error = await rejection(
      exchangeCode(provider, {
        code: "code",
        redirectUri: "https://app.test/cb",
        fetch: async () => new Response(oversized(), { status: 200 }),
      }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_TOKEN_EXCHANGE")).toBe(true);
    expect((error as Error).message).toBe(
      "[unauth/n] The token endpoint answered more than the 262144 bytes allowed.",
    );
    expect((error as Error).cause).toEqual({ reason: "too-large", status: 200 });
  });
});
