import { afterEach, beforeAll, describe, expect, expectTypeOf, it, vi } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type CustomProvider,
  type FlowResult,
  completeFlow,
  defineOAuth2Provider,
  defineProvider,
  defineSignInHandler,
  isUnauthError,
  startFlow,
} from "../../../src/n/index.ts";
import { handoffCarrier } from "../../../src/n/flow/_internal/carrier/handoff.ts";
import { completeFlowWithReturnHost } from "../../../src/n/flow/_internal/complete.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "./_fake-provider.ts";
import { sealedCarrier } from "../../../src/n/flow/_internal/carrier/sealed.ts";
import { cookieHeader, formStart } from "../_session.ts";

const APP = "https://app.test";
const MOVED = "https://ip.test";
const REDIRECT_URI = `${MOVED}/auth/custom`;
const IDP = "https://custom.test";

let key: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
});

afterEach(() => {
  vi.useRealTimers();
});

interface Link {
  userId: string;
}

/**
 * A provider that must start on `MOVED`: a start anywhere else is relocated there, query and all.
 * It vouches for `APP` itself; any other origin must come from the start options.
 */
function movingProvider(options: { trustedOrigins?: string[] } = { trustedOrigins: [APP] }) {
  const start = vi.fn(async (context: Parameters<CustomProvider["start"]>[0]) => {
    const here = new URL(context.request.url);
    if (here.origin !== MOVED) {
      const relocate = new URL(here.pathname + here.search, MOVED);
      return { relocate };
    }
    const url = new URL(`${IDP}/authorize`);
    url.searchParams.set("state", context.record.state);
    if (context.loginHint !== undefined) url.searchParams.set("login", context.loginHint);
    return { url };
  });
  const provider = defineProvider({
    id: "custom",
    kind: "custom",
    trustedOrigins: options.trustedOrigins,
    start,
    complete: async () => ({ identity: { subject: "acct-1", profile: {} } }),
  });
  return { provider, start };
}

/** The callback the provider sends the user back to, with the flow cookie `started` set. */
function callback(started: Response): Request {
  const state = new URL(started.headers.get("location")!).searchParams.get("state")!;
  return new Request(`${REDIRECT_URI}?state=${state}&code=c-1`, {
    headers: { cookie: cookieHeader(started.headers) },
  });
}

/** The carrier of the intent tokens, to open or forge one as the engine does. */
function intentCarrier() {
  return sealedCarrier<{ intent: Record<string, unknown>; returnHost: string }>(key, {
    typ: "unauth-intent+jwt",
    name: "unauth-intent",
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

describe("a relocated start", () => {
  it("seals the intent and the origin host into the relocation URL, and records nothing", async () => {
    const { provider } = movingProvider();
    const moved = await startFlow<Link>(provider, formStart(`${APP}/auth/custom?x=1`), {
      key,
      redirectUri: REDIRECT_URI,
      memo: { userId: "u1" },
      redirect: "/after",
    });

    const location = new URL(moved.headers.get("location")!);
    expect(location.origin).toBe(MOVED);
    expect(location.searchParams.get("x")).toBe("1");
    expect(location.searchParams.get("unauth_intent")).toMatch(/^eyJ/);
    expect([...location.searchParams.keys()]).toEqual(["x", "unauth_intent"]);
    expect(moved.headers.getSetCookie()).toEqual([]);
    expect(await intentCarrier().take(location.searchParams.get("unauth_intent")!)).toEqual({
      intent: { memo: { userId: "u1" }, redirect: "/after" },
      returnHost: "app.test",
    });
  });

  it("records the origin host when the relocated start runs on another host", async () => {
    const { provider } = movingProvider();
    const moved = await startFlow<Link>(provider, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const started = await startFlow<Link>(provider, new Request(moved.headers.get("location")!), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const { returnHost } = await completeFlowWithReturnHost<unknown, Link>(
      provider,
      callback(started),
      { key, headers: new Headers() },
    );
    expect(returnHost).toBe("app.test");
  });

  it("records no origin host when the token names the host the start runs on", async () => {
    const { provider } = movingProvider();
    const token = await intentCarrier().issue({ intent: {}, returnHost: "ip.test" });
    const started = await startFlow<Link>(
      provider,
      new Request(`${REDIRECT_URI}?unauth_intent=${token}`),
      { key, redirectUri: REDIRECT_URI },
    );
    const completed = await completeFlowWithReturnHost<unknown, Link>(provider, callback(started), {
      key,
      headers: new Headers(),
    });
    expect(completed).not.toHaveProperty("returnHost");
  });

  it("keeps the origin host out of the public result", async () => {
    const { provider } = movingProvider();
    const moved = await startFlow<Link>(provider, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const started = await startFlow<Link>(provider, new Request(moved.headers.get("location")!), {
      key,
      redirectUri: REDIRECT_URI,
    });
    const result = await completeFlow<unknown, Link>(provider, callback(started), {
      key,
      headers: new Headers(),
    });
    expect(result).not.toHaveProperty("returnHost");
    expectTypeOf<FlowResult>().not.toHaveProperty("returnHost");
  });

  it("merges the sealed intent over the relocated start's own options", async () => {
    const { provider, start } = movingProvider();
    const moved = await startFlow<Link>(provider, formStart(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
      memo: { userId: "u1" },
      redirect: "/after",
    });

    const started = await startFlow<Link>(provider, new Request(moved.headers.get("location")!), {
      key,
      redirectUri: REDIRECT_URI,
      redirect: "/elsewhere",
      loginHint: "bob",
    });
    expect(start.mock.calls[1]![0].loginHint).toBe("bob");
    const result = await completeFlow<unknown, Link>(provider, callback(started), {
      key,
      headers: new Headers(),
    });
    expect(result.memo).toEqual({ userId: "u1" });
    expect(result.redirect).toBe("/after");
  });

  it("refuses a replayed intent token", async () => {
    const { provider } = movingProvider();
    const moved = await startFlow<Link>(provider, formStart(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
      memo: { userId: "u1" },
    });
    const relocated = moved.headers.get("location")!;
    await startFlow(provider, new Request(relocated), { key, redirectUri: REDIRECT_URI });

    const error = await rejection(
      startFlow(provider, new Request(relocated), { key, redirectUri: REDIRECT_URI }),
    );
    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
    expect(error).toMatchObject({ status: 401, cause: { reason: "consumed" } });
  });

  it("refuses an expired intent token", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    const { provider } = movingProvider();
    const moved = await startFlow<Link>(provider, formStart(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
      memo: { userId: "u1" },
    });
    vi.setSystemTime(Date.now() + 2 * 60_000);

    const error = await rejection(
      startFlow(provider, new Request(moved.headers.get("location")!), {
        key,
        redirectUri: REDIRECT_URI,
      }),
    );
    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
    expect(error).toMatchObject({ cause: { reason: "consumed" } });
  });

  it("refuses a handoff token presented as an intent token", async () => {
    const { provider, start } = movingProvider();
    const token = await handoffCarrier<unknown, Link>(key).issue({
      identity: { provider: "custom", subject: "acct-1", profile: {} },
      memo: { userId: "u1" },
    });

    const error = await rejection(
      startFlow(provider, new Request(`${REDIRECT_URI}?unauth_intent=${token}`), {
        key,
        redirectUri: REDIRECT_URI,
      }),
    );
    expect(isUnauthError(error, "ERR_AUTHN_FLOW_EXPIRED")).toBe(true);
    expect(start).not.toHaveBeenCalled();
  });

  it("leaves a start without the parameter as it is", async () => {
    const { provider } = movingProvider();
    const started = await startFlow<Link>(provider, formStart(REDIRECT_URI), {
      key,
      redirectUri: REDIRECT_URI,
      memo: { userId: "u2" },
    });
    const { result, returnHost } = await completeFlowWithReturnHost<unknown, Link>(
      provider,
      callback(started),
      { key, headers: new Headers() },
    );
    expect(result.memo).toEqual({ userId: "u2" });
    expect(returnHost).toBeUndefined();
  });
});

describe("a start the deployment did not list", () => {
  const EVIL = "https://evil.test";

  it("is not relocated: nothing is sealed for a Host nobody configured, whatever the provider decides", async () => {
    const { provider, start } = movingProvider({});
    const error = await rejection(
      startFlow<Link>(provider, new Request(`${EVIL}/auth/custom`), {
        key,
        redirectUri: REDIRECT_URI,
      }),
    );
    expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    expect((error as Error).message).toMatch(/evil\.test[\s\S]*"trustedOrigins"/);
    expect(start).toHaveBeenCalledTimes(1);
  });

  it("is relocated once the start options or the provider list its origin", async () => {
    const { provider } = movingProvider({});
    const byOptions = await startFlow<Link>(provider, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
      trustedOrigins: [`${APP}/`],
    });
    expect(new URL(byOptions.headers.get("location")!).origin).toBe(MOVED);

    const vouching = movingProvider({ trustedOrigins: [APP] }).provider;
    const byProvider = await startFlow<Link>(vouching, new Request(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
    });
    expect(new URL(byProvider.headers.get("location")!).origin).toBe(MOVED);

    // Same host, another scheme or port: another origin.
    for (const origin of ["http://app.test", "https://app.test:8443"]) {
      const error = await rejection(
        startFlow<Link>(vouching, new Request(`${origin}/auth/custom`), {
          key,
          redirectUri: REDIRECT_URI,
        }),
      );
      expect(isUnauthError(error, "ERR_UNAUTH_CONFIG_INVALID")).toBe(true);
    }
  });

  it("is answered by the sign-in handler as a configuration failure, without a redirect", async () => {
    const { provider } = movingProvider({});
    const handler = defineSignInHandler(provider, {
      key,
      redirectUri: REDIRECT_URI,
      onSuccess: () => "ok",
    });
    const res = { headers: new Headers() };
    const answer = await handler({ req: new Request(`${EVIL}/auth/custom`), res });
    expect((answer as Response).status).toBe(500);
    expect((answer as Response).headers.get("location")).toBeNull();
    expect(res.headers.getSetCookie()).toEqual([]);
  });
});

describe("a provider that cannot relocate", () => {
  it("never reads the two parameters: a stray token on an OAuth route is just a query member", async () => {
    const fake = await createFakeProvider();
    const provider = defineOAuth2Provider({
      id: "fake",
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      authorization: `${ISSUER}/authorize`,
      token: `${ISSUER}/token`,
      userinfo: `${ISSUER}/userinfo`,
    });

    const start = await startFlow(provider, new Request(`${REDIRECT_URI}?unauth_intent=garbage`), {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
    });
    expect(start.status).toBe(302);

    const handler = defineSignInHandler(provider, {
      key,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: () => "ok",
    });
    const handed = await handler({
      req: new Request(`${REDIRECT_URI}?unauth_handoff=garbage`),
      res: { headers: new Headers() },
    });
    expect(handed).toBeInstanceOf(Response);
    expect((handed as Response).status).toBe(302);
  });
});

describe("the sealed carriers", () => {
  it("open their own tokens once, and refuse each other's", async () => {
    const intents = sealedCarrier<{ loginHint: string }>(key, {
      typ: "unauth-intent+jwt",
      name: "unauth-intent",
    });
    const handoffs = handoffCarrier<unknown, never>(key);
    const intent = await intents.issue({ loginHint: "alice" });
    const handoff = await handoffs.issue({
      identity: { provider: "custom", subject: "acct-1", profile: {} },
    });

    await expect(handoffs.take(intent)).rejects.toThrow(/"typ"/);
    await expect(intents.take(handoff)).rejects.toThrow(/"typ"/);
    expect(await intents.take(intent)).toEqual({ loginHint: "alice" });
    await expect(intents.take(intent)).rejects.toThrow("sealed token already used");
    expect((await handoffs.take(handoff)).identity.subject).toBe("acct-1");
  });

  it("refuses an intent token where the route expects a handoff", async () => {
    const { provider } = movingProvider();
    const handler = defineSignInHandler(provider, { key, onSuccess: () => "ok" });
    const moved = await startFlow<Link>(provider, formStart(`${APP}/auth/custom`), {
      key,
      redirectUri: REDIRECT_URI,
      memo: { userId: "u1" },
    });
    const token = new URL(moved.headers.get("location")!).searchParams.get("unauth_intent")!;

    const answer = await handler({
      req: new Request(`${APP}/auth/custom?unauth_handoff=${encodeURIComponent(token)}`),
      res: { headers: new Headers() },
    });
    expect((answer as Response).status).toBe(401);
  });
});
