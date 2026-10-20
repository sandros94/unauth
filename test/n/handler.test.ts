import { beforeAll, describe, expect, it, vi } from "vitest";
import { type JWK_oct, generateJWK } from "unjwt/session";

import {
  type HandlerEvent,
  type Provider,
  defineAuthSession,
  defineSignInHandler,
  isUnauthError,
  defineOAuth2Provider,
  defineSessionGuard,
} from "../../src/n/index.ts";
import { cookieJar } from "./_cookies.ts";
import { CLIENT_ID, CLIENT_SECRET, ISSUER, createFakeProvider } from "./flow/_fake-provider.ts";

const APP = "http://localhost";
const REDIRECT_URI = `${APP}/auth/fake`;

let key: JWK_oct<"A256GCM">;
let flowKey: JWK_oct<"A256GCM">;

beforeAll(async () => {
  key = await generateJWK("A256GCM");
  flowKey = await generateJWK("A256GCM");
});

interface User {
  userId: string;
  role?: string;
}

function fakeProvider(options: { responseMode?: "query" | "form_post" } = {}): Provider {
  return defineOAuth2Provider({
    id: "fake",
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    authorization: `${ISSUER}/authorize`,
    token: `${ISSUER}/token`,
    userinfo: `${ISSUER}/userinfo`,
    ...options,
  });
}

/** A web-standard event for `request`, with the `Headers` its response is sent with. */
function eventFor(request: Request): HandlerEvent & { res: { headers: Headers } } {
  return { req: request, res: { headers: new Headers() }, context: {} };
}

/** Runs a handler and turns what it returns into a `Response`, the way a runtime would. */
async function call(
  handler: (event: HandlerEvent) => Promise<unknown>,
  path: string,
  init: RequestInit = {},
): Promise<Response> {
  const event = eventFor(new Request(`${APP}${path}`, init));
  const result = await handler(event);
  if (result instanceof Response) {
    for (const line of event.res.headers.getSetCookie()) result.headers.append("set-cookie", line);
    return result;
  }
  return new Response(JSON.stringify(result), {
    headers: new Headers([...event.res.headers, ["content-type", "application/json"]]),
  });
}

describe("defineSignInHandler", () => {
  let fake: Awaited<ReturnType<typeof createFakeProvider>>;

  async function setup(overrides: Partial<Parameters<typeof defineSignInHandler>[1]> = {}) {
    fake = await createFakeProvider();
    const auth = defineAuthSession<User>({ key, cookie: { secure: false } });
    const handler = defineSignInHandler(fakeProvider(), {
      key: flowKey,
      cookie: { secure: false },
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: async (event, result) => {
        const session = await auth.use(event);
        await session.authenticate({ userId: result.identity.subject });
        return { subject: result.identity.subject, redirect: result.redirect ?? null };
      },
      ...overrides,
    });
    return { auth, handler };
  }

  async function signInFlow(handler: (event: HandlerEvent) => Promise<unknown>, jar = cookieJar()) {
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    const done = await call(handler, `${back.pathname}${back.search}`, {
      headers: { cookie: jar.toString() },
    });
    jar.update(done.headers);
    return { start, back, done, jar };
  }

  it("answers the first leg with a redirect to the provider and a flow cookie", async () => {
    const { handler } = await setup();
    const start = await call(handler, "/auth/fake");

    expect(start.status).toBe(302);
    expect(new URL(start.headers.get("location")!).origin).toBe(ISSUER);
    expect(start.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);
  });

  it("completes the callback leg, expires the flow cookie and hands the result to onSuccess", async () => {
    const { auth, handler } = await setup();
    const { done, jar } = await signInFlow(handler);

    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ subject: "user-1", redirect: null });
    const cookies = done.headers.getSetCookie();
    expect(cookies.some((line) => /^unauth-flow=[^;]*;.*Max-Age=0/i.test(line))).toBe(true);
    expect(cookies.some((line) => line.startsWith("unauth="))).toBe(true);

    const session = await auth.require(
      eventFor(new Request(APP, { headers: { cookie: jar.toString() } })),
    );
    expect(session.data).toMatchObject({
      userId: "user-1",
      authenticatedAt: expect.any(Number),
    });
  });

  it("passes onStart's intent through the flow", async () => {
    const { handler } = await setup({ onStart: () => ({ redirect: "/dashboard" }) });
    const { done } = await signInFlow(handler);

    expect(await done.json()).toEqual({ subject: "user-1", redirect: "/dashboard" });
  });

  it("answers an UnauthError with its status and message, the flow cookie expired on that response", async () => {
    const { handler } = await setup();
    const jar = cookieJar();
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    back.searchParams.set("state", "forged");

    const event = eventFor(new Request(back, { headers: { cookie: jar.toString() } }));
    const res = await handler(event);

    expect(res).toBeInstanceOf(Response);
    const response = res as Response;
    expect(response.status).toBe(401);
    expect(await response.text()).toMatch(/does not belong/);
    expect(response.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);
    expect(event.res.headers.getSetCookie()).toEqual([]);
  });

  it("hands UnauthErrors to onError when given, the flow cookie expired on the event", async () => {
    const onError = vi.fn((_event: HandlerEvent, error: unknown) => ({
      failed: isUnauthError(error) && error.code,
    }));
    const { handler } = await setup({ onError });
    const jar = cookieJar();
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);
    back.searchParams.set("error", "access_denied");

    const event = eventFor(new Request(back, { headers: { cookie: jar.toString() } }));
    const result = await handler(event);

    expect(result).toEqual({ failed: "ERR_AUTHN_PROVIDER_REFUSED" });
    expect(onError).toHaveBeenCalledOnce();
    expect(event.res.headers.getSetCookie().join("\n")).toMatch(/unauth-flow=/);
  });

  it("hides configuration details behind a 500", async () => {
    fake = await createFakeProvider();
    const handler = defineSignInHandler(fakeProvider(), { key: flowKey, onSuccess: () => "ok" });

    const res = await call(handler, "/auth/fake");

    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain("redirectUri");
  });

  it("completes a form_post callback posted to the same route", async () => {
    fake = await createFakeProvider();
    const handler = defineSignInHandler(fakeProvider({ responseMode: "form_post" }), {
      key: flowKey,
      redirectUri: REDIRECT_URI,
      fetch: fake.fetch,
      onSuccess: (_event, result) => ({ subject: result.identity.subject }),
    });
    const jar = cookieJar();
    const start = await call(handler, "/auth/fake");
    jar.update(start.headers);
    const back = fake.approve(start.headers.get("location")!);

    const done = await call(handler, "/auth/fake", {
      method: "POST",
      headers: { "cookie": jar.toString(), "content-type": "application/x-www-form-urlencoded" },
      body: back.searchParams.toString(),
    });

    expect(done.status).toBe(200);
    expect(await done.json()).toEqual({ subject: "user-1" });
  });

  it("rethrows anything that is not an UnauthError", async () => {
    const { handler } = await setup({
      onStart: () => {
        throw new TypeError("boom");
      },
    });

    await expect(call(handler, "/auth/fake")).rejects.toThrow(TypeError);
  });
});

describe("session middleware", () => {
  async function signedInEvent(auth: ReturnType<typeof defineAuthSession<User>>, path = "/") {
    const login = eventFor(new Request(APP));
    await (await auth.use(login)).authenticate({ userId: "u1" });
    const jar = cookieJar();
    jar.update(login.res.headers);
    return eventFor(new Request(`${APP}${path}`, { headers: { cookie: jar.toString() } }));
  }

  it("defineSessionGuard answers 401 without an authenticated session, nothing with one", async () => {
    const auth = defineAuthSession<User>({ key, cookie: { secure: false } });
    const guard = defineSessionGuard(auth);

    const refused = await guard(eventFor(new Request(APP)));
    expect(refused).toBeInstanceOf(Response);
    expect(refused?.status).toBe(401);

    expect(await guard(await signedInEvent(auth))).toBeUndefined();
  });

  it("runs onAuthenticated with the session and the context, and lets it refuse", async () => {
    const auth = defineAuthSession<User>({ key, cookie: { secure: false } });
    const onAuthenticated = vi.fn(({ session }: { session: { data: User } }) => {
      if (session.data.userId !== "u1") throw new Error("not you");
    });
    const guard = defineSessionGuard(auth, { onAuthenticated });
    const event = await signedInEvent(auth);

    expect(await guard(event)).toBeUndefined();
    expect(onAuthenticated).toHaveBeenCalledOnce();
    expect(onAuthenticated.mock.calls[0]![0]).toMatchObject({ context: event });
  });

  it("hands onAuthenticated the live session, which the handler shares through require()", async () => {
    const auth = defineAuthSession<User>({ key, cookie: { secure: false } });
    const guard = defineSessionGuard(auth, {
      onAuthenticated: async ({ session }) => {
        await session.update({ role: "guarded" });
      },
    });
    const event = await signedInEvent(auth);

    expect(await guard(event)).toBeUndefined();
    expect((await auth.require(event)).data).toMatchObject({ userId: "u1", role: "guarded" });
  });
});
