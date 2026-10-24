import { describe, expect, it } from "vitest";

import { type Fetch, readObject } from "../../../src/n/flow/_internal/http/shared.ts";
import { getJson } from "../../../src/n/flow/_internal/http/json.ts";
import { postForm, postText } from "../../../src/n/flow/_internal/http/form.ts";
import { PROVIDER_DOCUMENT_MAX_BYTES } from "../../../src/n/flow/_internal/http/body.ts";
import { defineOAuth2Provider, exchangeCode, isUnauthError } from "../../../src/n/index.ts";

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
    expect(isUnauthError(error) && error.status).toBe(502);
    expect((error as Error).message).toMatch(/did not answer within 20 ms/);
    expect((error as Error).cause).toMatchObject({ reason: "timeout" });
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
    expect((error as Error).cause).toEqual({ reason: "too-large", status: 200 });
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
    expect((error as Error).cause).toMatchObject({ reason: "malformed", status: 200 });
  });

  it("names the status of a failed answer", async () => {
    const { fetch } = recording(async () => new Response("down", { status: 503 }));

    const error = await rejection(getJson(URL_, { fetch, label: "document" }));

    expect((error as Error).message).toMatch(/answered 503/);
    expect((error as Error).cause).toEqual({ reason: "status", status: 503 });
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

  it("makes exchangeCode surface an oversized token response as the provider's failure", async () => {
    const provider = defineOAuth2Provider({
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

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toBe(
      "[unauth/n] The token endpoint at https://idp.test/token answered more than the 262144 bytes allowed.",
    );
    expect((error as Error).cause).toEqual({ reason: "too-large", status: 200 });
  });
});

describe("postForm", () => {
  const form = () => new URLSearchParams({ grant_type: "authorization_code", code: "c1" });

  it("POSTs the form with its own content type, the caller's headers, a signal and no redirects", async () => {
    const { fetch, inits } = recording(async () => Response.json({ ok: true }));

    const answer = await postForm(URL_, form(), {
      fetch,
      headers: { dpop: "proof" },
      label: "endpoint",
    });

    expect(answer).toMatchObject({ ok: true, status: 200, body: { ok: true } });
    expect(inits[0]?.method).toBe("POST");
    expect(inits[0]?.body).toBeInstanceOf(URLSearchParams);
    expect(inits[0]?.redirect).toBe("error");
    expect(inits[0]?.signal).toBeInstanceOf(AbortSignal);
    const headers = new Headers(inits[0]?.headers);
    expect(headers.get("content-type")).toBe("application/x-www-form-urlencoded");
    expect(headers.get("accept")).toBe("application/json");
    expect(headers.get("dpop")).toBe("proof");
  });

  it("hands a failed status back with its headers and an urlencoded body", async () => {
    const { fetch } = recording(
      async () =>
        new Response("error=use_dpop_nonce", {
          status: 400,
          headers: { "content-type": "application/x-www-form-urlencoded", "dpop-nonce": "n1" },
        }),
    );

    const answer = await postForm(URL_, form(), { fetch, label: "endpoint" });

    expect(answer.ok).toBe(false);
    expect(answer.status).toBe(400);
    expect(answer.body).toEqual({ error: "use_dpop_nonce" });
    expect(answer.headers.get("dpop-nonce")).toBe("n1");
  });

  it("reads a body that is not an object as undefined", async () => {
    const { fetch } = recording(async () => new Response("<html>oops</html>", { status: 502 }));

    const answer = await postForm(URL_, form(), { fetch, label: "endpoint" });

    expect(answer).toMatchObject({ ok: false, status: 502, body: undefined });
  });

  it("gives up on an endpoint that never answers, aborting the request", async () => {
    const { fetch, inits } = recording(() => new Promise<Response>(() => {}));

    const error = await rejection(
      postForm(URL_, form(), { fetch, label: "endpoint", timeout: 20 }),
    );

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toMatch(/did not answer within 20 ms/);
    expect((error as Error).cause).toMatchObject({ reason: "timeout" });
    expect(inits[0]?.signal?.aborted).toBe(true);
  });

  it("refuses an oversized body, naming the status it came with", async () => {
    const chunk = new Uint8Array(64 * 1024).fill(0x20);
    const { body } = streamed([chunk, chunk, chunk, chunk, chunk]);
    const { fetch } = recording(async () => new Response(body, { status: 201 }));

    const error = await rejection(postForm(URL_, form(), { fetch, label: "endpoint" }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect(isUnauthError(error) && error.status).toBe(502);
    expect((error as Error).message).toMatch(/more than the 262144 bytes allowed/);
    expect((error as Error).cause).toEqual({ reason: "too-large", status: 201 });
  });

  it("reports a network failure as unreachable, with the failure underneath", async () => {
    const boom = new TypeError("fetch failed");
    const { fetch } = recording(async () => {
      throw boom;
    });

    const error = await rejection(postForm(URL_, form(), { fetch, label: "endpoint" }));

    expect(isUnauthError(error, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((error as Error).message).toMatch(/Could not reach the endpoint/);
    expect((error as Error).cause).toEqual({ reason: "unreachable", cause: boom });
  });
});

describe("endpoint names in messages", () => {
  it("drop the query, where a credential may travel", async () => {
    const { fetch } = recording(async () => new Response("nope", { status: 503 }));

    const error = await rejection(
      getJson("https://api.test/summary?key=top-secret&ids=1", { fetch, label: "Web API" }),
    );

    expect((error as Error).message).toBe(
      "[unauth/n] The Web API at https://api.test/summary answered 503.",
    );
    expect((error as Error).message).not.toContain("top-secret");
  });
});

describe("postText", () => {
  const form = () => new URLSearchParams({ "openid.mode": "check_authentication" });

  it("POSTs the form asking for text and hands the body back with its status", async () => {
    const { fetch, inits } = recording(
      async () => new Response("ns:x\nis_valid:true\n", { status: 200 }),
    );

    const answer = await postText(URL_, form(), { fetch, label: "endpoint" });

    expect(answer).toMatchObject({ ok: true, status: 200, text: "ns:x\nis_valid:true\n" });
    expect(new Headers(inits[0]?.headers).get("accept")).toBe("text/plain");
    expect(new Headers(inits[0]?.headers).get("content-type")).toBe(
      "application/x-www-form-urlencoded",
    );
    expect(inits[0]?.redirect).toBe("error");
  });

  it("leaves a failing status to the caller", async () => {
    const { fetch } = recording(async () => new Response("busy", { status: 503 }));

    await expect(postText(URL_, form(), { fetch, label: "endpoint" })).resolves.toMatchObject({
      ok: false,
      status: 503,
      text: "busy",
    });
  });

  it("refuses an oversized body and malformed UTF-8", async () => {
    const chunk = new Uint8Array(64 * 1024).fill(0x20);
    const { body } = streamed([chunk, chunk, chunk, chunk, chunk]);
    const big = await rejection(
      postText(URL_, form(), { fetch: async () => new Response(body), label: "endpoint" }),
    );
    expect((big as Error).cause).toEqual({ reason: "too-large", status: 200 });

    const bad = await rejection(
      postText(URL_, form(), {
        fetch: async () => new Response(new Uint8Array([0xff, 0xfe])),
        label: "endpoint",
      }),
    );
    expect(isUnauthError(bad, "ERR_AUTHN_PROVIDER_ERROR")).toBe(true);
    expect((bad as Error).message).toMatch(/did not answer text/);
    expect((bad as Error).cause).toMatchObject({ reason: "malformed", status: 200 });
  });
});
