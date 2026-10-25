import { beforeAll, describe, expect, it } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type OAuthProvider,
  type UnauthError,
  completeFlow,
  defineOAuth2Provider,
  defineSignInHandler,
  isUnauthError,
  startFlow,
} from "../../../src/n/index.ts";
import { cookieHeader } from "../_session.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "./_fake-provider.ts";

const APP = "https://app.test";
const REDIRECT_URI = `${APP}/auth/fake`;
const CAP = 65_536;
const CHUNK = 16_384;

let key: JWK_oct<"A256GCM">;
/** What constructing a `Request` on a stream pulls by itself, before anyone reads the body. */
let prefetch: number;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
  const probe = streamed(2 * 1024 * 1024);
  post(probe.body);
  await new Promise((resolve) => setTimeout(resolve, 10));
  prefetch = probe.pulled();
});

function provider(responseMode: "query" | "form_post"): OAuthProvider {
  return defineOAuth2Provider({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
    responseMode,
  });
}

/** A body of `size` bytes streamed in chunks, counting what the reader pulled. */
function streamed(
  size: number,
  prefix = "",
): { body: ReadableStream<Uint8Array>; pulled: () => number } {
  let sent = 0;
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= size) {
        controller.close();
        return;
      }
      const chunk =
        sent === 0 && prefix
          ? encoder.encode(prefix.padEnd(Math.min(CHUNK, size), "a"))
          : new Uint8Array(Math.min(CHUNK, size - sent)).fill(97);
      sent += chunk.byteLength;
      controller.enqueue(chunk);
    },
  });
  return { body, pulled: () => sent };
}

function post(body: BodyInit, headers: Record<string, string> = {}, url = REDIRECT_URI): Request {
  return new Request(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body,
    // @ts-expect-error streamed request bodies need the half-duplex flag
    duplex: "half",
  });
}

/** `startFlow` and the provider's consent on a `form_post` provider: the flow cookie and the fields to post back. */
async function begin(oauth: OAuthProvider, fake: Awaited<ReturnType<typeof createFakeProvider>>) {
  const response = await startFlow(oauth, new Request(`${APP}/auth/fake`), {
    key,
    redirectUri: REDIRECT_URI,
    fetch: fake.fetch,
  });
  const back = fake.approve(new URL(response.headers.get("location")!));
  return { cookie: cookieHeader(response.headers), fields: back.searchParams.toString() };
}

async function rejection(promise: Promise<unknown>): Promise<UnauthError> {
  const error: unknown = await promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (thrown: unknown) => thrown,
  );
  if (!isUnauthError(error)) throw error;
  return error;
}

describe("the callback body", () => {
  it("is not read for a request that carries no flow", async () => {
    const fake = await createFakeProvider();
    for (const oauth of [provider("query"), provider("form_post")]) {
      const { body, pulled } = streamed(2 * 1024 * 1024);
      const url = oauth.responseMode === "query" ? `${REDIRECT_URI}?code=x` : REDIRECT_URI;
      const error = await rejection(
        completeFlow(oauth, post(body, {}, url), {
          key,
          headers: new Headers(),
          fetch: fake.fetch,
        }),
      );
      expect(error.code).toBe("ERR_AUTHN_FLOW_EXPIRED");
      expect(error.cause).toEqual({ reason: "missing" });
      expect(pulled()).toBe(prefetch);
    }
    expect(fake.requests).toHaveLength(0);
  });

  it("is never read on a provider that answers in the query", async () => {
    const fake = await createFakeProvider();
    const oauth = provider("query");
    const { cookie, fields } = await begin(oauth, fake);
    const { body, pulled } = streamed(2 * 1024 * 1024);

    const result = await completeFlow(oauth, post(body, { cookie }, `${REDIRECT_URI}?${fields}`), {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });
    expect(result.identity.subject).toBe("user-1");
    expect(pulled()).toBe(prefetch);
  });

  it("is read up to the cap on a form_post provider, and refused unread past it", async () => {
    const fake = await createFakeProvider();
    const oauth = provider("form_post");
    const { cookie, fields } = await begin(oauth, fake);

    const within = await completeFlow(oauth, post(fields, { cookie }), {
      key,
      headers: new Headers(),
      fetch: fake.fetch,
    });
    expect(within.identity.subject).toBe("user-1");

    const again = await begin(oauth, fake);
    const { body, pulled } = streamed(2 * 1024 * 1024, `${again.fields}&pad=`);
    const headers = new Headers();
    const error = await rejection(
      completeFlow(oauth, post(body, { cookie: again.cookie }), {
        key,
        headers,
        fetch: fake.fetch,
      }),
    );
    expect(error.code).toBe("ERR_AUTHN_CALLBACK_INVALID");
    expect(error.status).toBe(400);
    expect(error.cause).toEqual({ reason: "too-large" });
    expect(pulled()).toBeLessThanOrEqual(CAP + CHUNK + prefetch);
    expect(headers.getSetCookie().join("\n")).toMatch(/__Host-unauth-flow=;/);
  });

  it("refuses a declared length over the cap without reading", async () => {
    const fake = await createFakeProvider();
    const oauth = provider("form_post");
    const { cookie } = await begin(oauth, fake);
    const { body, pulled } = streamed(CAP + 1);

    const error = await rejection(
      completeFlow(oauth, post(body, { cookie, "content-length": String(CAP + 1) }), {
        key,
        headers: new Headers(),
        fetch: fake.fetch,
      }),
    );
    expect(error.code).toBe("ERR_AUTHN_CALLBACK_INVALID");
    expect(pulled()).toBe(prefetch);
  });

  it("answers an anonymous oversized post through the sign-in handler with a 401, nothing read", async () => {
    const fake = await createFakeProvider();
    const handler = defineSignInHandler(provider("form_post"), {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: () => "ok",
    });
    const { body, pulled } = streamed(4 * 1024 * 1024);
    const answer = await handler({ req: post(body), res: { headers: new Headers() } });
    expect((answer as Response).status).toBe(401);
    expect(pulled()).toBe(prefetch);
    expect(fake.requests).toHaveLength(0);
  });
});
