import { describe, expect, it } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type FlowKey,
  type OAuthProvider,
  type StartFlowOptions,
  completeFlow,
  defineOAuth2Provider,
  deriveJWK,
  defineSignInHandler,
  isUnauthError,
  startFlow,
} from "../../../src/n/index.ts";
import { cookieHeader } from "../_session.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "./_fake-provider.ts";

const APP = "https://app.test";
const REDIRECT_URI = `${APP}/auth/fake`;
const DIR = { alg: "dir", enc: "A256GCM" } as const;

function fakeOAuth2(): OAuthProvider {
  return defineOAuth2Provider({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
  });
}

function secretCryptoKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** `startFlow` under `options`, and the provider's callback carrying the flow cookie it set. */
async function begin(
  fake: Awaited<ReturnType<typeof createFakeProvider>>,
  options: Pick<StartFlowOptions, "key" | "jwe">,
): Promise<Request> {
  const response = await startFlow(fakeOAuth2(), new Request(REDIRECT_URI), {
    ...options,
    redirectUri: REDIRECT_URI,
    fetch: fake.fetch,
  });
  const back = fake.approve(response.headers.get("location")!);
  return new Request(back, { headers: { cookie: cookieHeader(response.headers) } });
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (error: unknown) => error,
  );
}

describe("a CryptoKey flow key", () => {
  it("runs a sign-in once `jwe` names its algorithms", async () => {
    const fake = await createFakeProvider();
    const key = await secretCryptoKey();
    const request = await begin(fake, { key, jwe: DIR });

    const result = await completeFlow(fakeOAuth2(), request, {
      key,
      jwe: DIR,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity.subject).toBe("user-1");
  });

  it("is refused without `jwe`, before any redirect, on either leg", async () => {
    const fake = await createFakeProvider();
    const key = await secretCryptoKey();

    const started = await rejection(
      startFlow(fakeOAuth2(), new Request(REDIRECT_URI), {
        key,
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
      }),
    );
    expect(isUnauthError(started, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((started as Error).message).toMatch(/naming no algorithm[\s\S]*"jwe"/);

    const request = await begin(fake, { key, jwe: DIR });
    const completed = await rejection(
      completeFlow(fakeOAuth2(), request, { key, headers: new Headers(), fetch: fake.fetch }),
    );
    expect(isUnauthError(completed, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect(fake.requests.filter((r) => r.url.pathname === "/token")).toHaveLength(0);
  });

  it("is refused without `jwe` where the handler is defined, or as a 500 when a callback resolves it", async () => {
    const fake = await createFakeProvider();
    const errors: unknown[] = [];
    const key = await secretCryptoKey();
    let defined: unknown;
    try {
      defineSignInHandler(fakeOAuth2(), {
        key,
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
        onSuccess: () => undefined,
      });
    } catch (error) {
      defined = error;
    }
    expect(isUnauthError(defined, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((defined as Error).message).toMatch(/"jwe"/);

    const hooked = defineSignInHandler(fakeOAuth2(), {
      key: () => key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: () => undefined,
      onError: (_event, error) => {
        errors.push(error);
        return new Response(null, { status: error.status });
      },
    });
    const res = { headers: new Headers() };
    const answer = await hooked({ req: new Request(REDIRECT_URI), res });
    expect(answer.status).toBe(500);
    expect(answer.headers.has("location")).toBe(false);
    expect(answer.headers.getSetCookie()).toEqual([]);
    expect(res.headers.getSetCookie()).toEqual([]);
    expect(errors).toHaveLength(1);
    expect(isUnauthError(errors[0], "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("runs a sign-in through the handler once `jwe` names its algorithms", async () => {
    const fake = await createFakeProvider();
    const handler = defineSignInHandler(fakeOAuth2(), {
      key: await secretCryptoKey(),
      jwe: DIR,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: (_event, result) => result.identity.subject,
    });

    const started = (await handler({
      req: new Request(REDIRECT_URI),
      res: { headers: new Headers() },
    })) as Response;
    expect(started.status).toBe(302);
    const back = fake.approve(started.headers.get("location")!);
    const answer = await handler({
      req: new Request(back, { headers: { cookie: cookieHeader(started.headers) } }),
      res: { headers: new Headers() },
    });
    expect(answer).toBe("user-1");
  });
});

describe("a JWK Set flow key", () => {
  let before: JWK_oct<"A256GCM">;
  let after: JWK_oct<"A256GCM">;
  let rotated: FlowKey;

  async function keys() {
    before = await generateJWK("A256GCM");
    after = await generateJWK("A256GCM");
    rotated = { keys: [after, before] };
  }

  it("completes a sign-in started under a key it holds after its first", async () => {
    await keys();
    const fake = await createFakeProvider();
    const request = await begin(fake, { key: before });

    const result = await completeFlow(fakeOAuth2(), request, {
      key: rotated,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity.subject).toBe("user-1");
  });

  it("completes across a rotation of `deriveJWK` keys, each token naming the `kid` of the key that sealed it", async () => {
    const fake = await createFakeProvider();
    const old = await deriveJWK("an-old-flow-secret-of-at-least-32-characters", { info: "flow" });
    const next = await deriveJWK("a-new-flow-secret-of-at-least-32-characters", { info: "flow" });
    const request = await begin(fake, { key: old });
    const token = request.headers.get("cookie")!.split("=")[1]!;
    const header = JSON.parse(atob(token.split(".")[0]!.replaceAll("-", "+").replaceAll("_", "/")));

    const result = await completeFlow(fakeOAuth2(), request, {
      key: { keys: [next, old] },
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity.subject).toBe("user-1");
    expect(header.kid).toBe(old.kid);
    expect(old.kid).not.toBe(next.kid);
  });

  it("seals with its first key: its flow cookie opens under that key alone, not under the old one", async () => {
    await keys();
    const fake = await createFakeProvider();
    const request = await begin(fake, { key: rotated });

    const old = await rejection(
      completeFlow(fakeOAuth2(), request.clone(), {
        key: before,
        headers: new Headers(),
        fetch: fake.fetch,
      }),
    );
    expect(isUnauthError(old, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
    expect((old as Error).cause).toEqual({ reason: "unreadable" });

    const result = await completeFlow(fakeOAuth2(), request, {
      key: after,
      headers: new Headers(),
      fetch: fake.fetch,
    });
    expect(result.identity.subject).toBe("user-1");
  });

  it("opens under `jwe` what an entry naming no `alg` sealed, and is refused without `jwe`", async () => {
    await keys();
    const fake = await createFakeProvider();
    const { alg: _alg, ...bare } = await generateJWK("A256GCM");
    const set = { keys: [after, bare] } as FlowKey;

    const fromOld = await begin(fake, { key: bare, jwe: DIR });
    const result = await completeFlow(fakeOAuth2(), fromOld.clone(), {
      key: set,
      jwe: DIR,
      headers: new Headers(),
      fetch: fake.fetch,
    });
    expect(result.identity.subject).toBe("user-1");

    const refused = await rejection(
      completeFlow(fakeOAuth2(), fromOld, { key: set, headers: new Headers(), fetch: fake.fetch }),
    );
    expect(isUnauthError(refused, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((refused as Error).message).toMatch(/naming no algorithm[\s\S]*"jwe"/);
    let defined: unknown;
    try {
      defineSignInHandler(fakeOAuth2(), {
        key: set,
        redirectUri: REDIRECT_URI,
        onSuccess: () => undefined,
      });
    } catch (error) {
      defined = error;
    }
    expect(isUnauthError(defined, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
  });

  it("is refused where the handler is defined when empty or holding a key that is not an oct JWK", async () => {
    await keys();
    const pair = await generateJWK("RSA-OAEP-256");
    for (const set of [{ keys: [] }, { keys: [after, pair.publicKey] }]) {
      let defined: unknown;
      try {
        defineSignInHandler(fakeOAuth2(), {
          key: set as FlowKey,
          redirectUri: REDIRECT_URI,
          onSuccess: () => undefined,
        });
      } catch (error) {
        defined = error;
      }
      expect(isUnauthError(defined, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
      expect((defined as Error).message).toMatch(/JWK Set/);
    }
  });
});
