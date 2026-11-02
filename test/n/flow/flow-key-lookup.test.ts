import { describe, expect, it, vi } from "vitest";
import { isJWTError } from "unjwt/error";
import { generateJWK } from "unjwt/session";

import {
  type FlowKey,
  type FlowKeyLookup,
  type OAuthProvider,
  type StartFlowOptions,
  completeFlow,
  defineOAuth2Provider,
  defineSignInHandler,
  UnauthError,
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

describe("a flow key lookup", () => {
  it("opens a flow cookie under the key it picks by the token's `kid`, in place of `key`", async () => {
    const fake = await createFakeProvider();
    const old = await generateJWK("A256GCM");
    const onKeyLookup = vi.fn<FlowKeyLookup>(() => ({ keys: [old] }));
    const request = await begin(fake, { key: old });

    const result = await completeFlow(fakeOAuth2(), request, {
      key: await generateJWK("A256GCM"),
      onKeyLookup,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity.subject).toBe("user-1");
    expect(onKeyLookup).toHaveBeenCalledTimes(1);
    const args = onKeyLookup.mock.calls[0]![0];
    expect(Object.keys(args)).toEqual(["header", "event"]);
    expect(args.header).toMatchObject({ kid: old.kid, typ: "unauth-flow+jwt" });
    expect(args.event!.req.url).toBe(request.url);
  });

  it("picks a key from the request the cookie comes with: a tenant's, by host", async () => {
    const tenants = {
      "app.test": await generateJWK("A256GCM"),
      "other.test": await generateJWK("A256GCM"),
    };
    const onKeyLookup: FlowKeyLookup = ({ event }) => {
      const host = new URL(event!.req.url).hostname as keyof typeof tenants;
      return tenants[host];
    };
    const complete = async (request: Request) => {
      const fake = await createFakeProvider();
      const back = await begin(fake, { key: tenants["app.test"] });
      const url = new URL(back.url);
      url.host = new URL(request.url).host;
      return completeFlow(fakeOAuth2(), new Request(url, { headers: back.headers }), {
        key: await generateJWK("A256GCM"),
        onKeyLookup,
        headers: new Headers(),
        fetch: fake.fetch,
      });
    };

    expect((await complete(new Request(APP))).identity.subject).toBe("user-1");
    const error = await rejection(complete(new Request("https://other.test")));
    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
    expect((error as Error).cause).toEqual({ reason: "unreadable" });
  });

  it("opens under `jwe.alg` a key it returns naming no `alg`", async () => {
    const fake = await createFakeProvider();
    const { alg: _alg, ...bare } = await generateJWK("A256GCM");
    const request = await begin(fake, { key: bare, jwe: DIR });

    const result = await completeFlow(fakeOAuth2(), request, {
      key: await generateJWK("A256GCM"),
      jwe: DIR,
      onKeyLookup: () => bare as FlowKey,
      headers: new Headers(),
      fetch: fake.fetch,
    });

    expect(result.identity.subject).toBe("user-1");
  });

  it("fails the flow as expired when it returns no key, or an empty JWK Set", async () => {
    const lookups: FlowKeyLookup[] = [() => undefined, () => ({ keys: [] })];
    for (const onKeyLookup of lookups) {
      const fake = await createFakeProvider();
      const key = await generateJWK("A256GCM");
      const request = await begin(fake, { key });

      const error = await rejection(
        completeFlow(fakeOAuth2(), request, {
          key,
          onKeyLookup,
          headers: new Headers(),
          fetch: fake.fetch,
        }),
      );
      expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
      expect((error as Error).cause).toEqual({ reason: "unreadable" });
      expect(fake.requests.filter((r) => r.url.pathname === "/token")).toHaveLength(0);
    }
  });

  it("propagates what it throws as it is, an `UnauthError` included, leaving the flow cookie alone", async () => {
    const thrown = [
      new Error("kms down"),
      new UnauthError("[app] No such tenant.", "ERR_APP_TENANT", { status: 404 }),
    ];
    for (const down of thrown) {
      const fake = await createFakeProvider();
      const key = await generateJWK("A256GCM");
      const request = await begin(fake, { key });
      const headers = new Headers();

      const error = await rejection(
        completeFlow(fakeOAuth2(), request, {
          key,
          onKeyLookup: () => {
            throw down;
          },
          headers,
          fetch: fake.fetch,
        }),
      );
      expect(error).toBe(down);
      expect(headers.getSetCookie()).toEqual([]);
      expect(fake.requests.filter((r) => r.url.pathname === "/token")).toHaveLength(0);
      const result = await completeFlow(fakeOAuth2(), new Request(request), {
        key,
        onKeyLookup: () => key,
        headers: new Headers(),
        fetch: fake.fetch,
      });
      expect(result.identity.subject).toBe("user-1");
    }
  });

  it("rejects with unjwt's `ERR_JWK_INVALID` a key it returns that cannot open the flow cookie, leaving the cookie alone", async () => {
    const fake = await createFakeProvider();
    const key = await generateJWK("A256GCM");
    const request = await begin(fake, { key });
    const headers = new Headers();

    const error = await rejection(
      completeFlow(fakeOAuth2(), request, {
        key,
        onKeyLookup: () => ({ kty: "oct", k: "AAAA", alg: "A256GCM" }),
        headers,
        fetch: fake.fetch,
      }),
    );
    expect(isJWTError(error, "ERR_JWK_INVALID")).toBe(true);
    expect(headers.getSetCookie()).toEqual([]);
    expect(fake.requests.filter((r) => r.url.pathname === "/token")).toHaveLength(0);
  });

  it("propagates what it throws reading the cookie a new sign-in replaces", async () => {
    const fake = await createFakeProvider();
    const key = await generateJWK("A256GCM");
    const callback = await begin(fake, { key });
    const down = new Error("kms down");

    const error = await rejection(
      startFlow(fakeOAuth2(), new Request(REDIRECT_URI, { headers: callback.headers }), {
        key,
        onKeyLookup: () => {
          throw down;
        },
        redirectUri: REDIRECT_URI,
        fetch: fake.fetch,
      }),
    );
    expect(error).toBe(down);
  });

  it("reaches the flow through the sign-in handler", async () => {
    const fake = await createFakeProvider();
    const old = await generateJWK("A256GCM");
    const kids: unknown[] = [];
    const options = {
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: (_event: unknown, result: { identity: { subject: string } }) =>
        result.identity.subject,
    };
    const before = defineSignInHandler(fakeOAuth2(), { ...options, key: old });
    const after = defineSignInHandler(fakeOAuth2(), {
      ...options,
      key: await generateJWK("A256GCM"),
      onKeyLookup: ({ header }) => {
        kids.push(header.kid);
        return { keys: [old] };
      },
    });

    const started = (await before({
      req: new Request(REDIRECT_URI),
      res: { headers: new Headers() },
    })) as Response;
    const back = fake.approve(started.headers.get("location")!);
    const answer = await after({
      req: new Request(back, { headers: { cookie: cookieHeader(started.headers) } }),
      res: { headers: new Headers() },
    });

    expect(answer).toBe("user-1");
    expect(kids).toEqual([old.kid]);
  });

  it("propagates through the sign-in handler what it throws: no `onError`, no answer, the flow cookie kept", async () => {
    const fake = await createFakeProvider();
    const key = await generateJWK("A256GCM");
    const down = new Error("kms down");
    const onError = vi.fn(() => "answered");
    const handler = defineSignInHandler(fakeOAuth2(), {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onKeyLookup: () => {
        throw down;
      },
      onSuccess: () => "ok",
      onError,
    });
    const request = await begin(fake, { key });
    const res = { headers: new Headers() };

    expect(await rejection(handler({ req: request, res }))).toBe(down);
    expect(onError).not.toHaveBeenCalled();
    expect(res.headers.getSetCookie()).toEqual([]);
  });
});
